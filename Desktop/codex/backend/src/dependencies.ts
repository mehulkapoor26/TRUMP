import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import semver from 'semver';
import type { DependencyGraph, DependencyKind, DependencyNode } from '@traceguard/shared';
import { ScanError } from './errors.js';

export interface NpmDocument { path: string; data: unknown }
type ObjectValue = Record<string, unknown>;
const object = (value: unknown): value is ObjectValue => !!value && typeof value === 'object' && !Array.isArray(value);
const own = (value: ObjectValue, key: string) => Object.hasOwn(value, key) ? value[key] : undefined;
const text = (value: unknown) => typeof value === 'string' && value.length > 0 ? value : undefined;
const ref = (context: string, path: string) => `urn:traceguard:component:${createHash('sha256').update(`${context}\0${path}`).digest('hex')}`;
const safePath = (path: string) => path.length <= 1024 && !/[\\\x00-\x1f\x7f:]/.test(path) && !path.split('/').some(p => !p || p === '.' || p === '..');
const packageName = (name: string) => /^(?:@[a-zA-Z0-9_.~-]+\/)?[a-zA-Z0-9_.~-]+$/.test(name) && name !== '.' && name !== '..' && name.length <= 214;

function declarations(data: ObjectValue, includeDev: boolean, legacy = false) {
  const output: { name: string; requested: string; kind: DependencyKind; optionalPeer?: boolean }[] = [];
  const fields: [string, DependencyKind][] = legacy ? [['requires', 'runtime']] : [['dependencies', 'runtime'], ['optionalDependencies', 'optional'], ['peerDependencies', 'peer'], ...(includeDev ? [['devDependencies', 'dev'] as [string, DependencyKind]] : [])];
  for (const [field, kind] of fields) {
    const values = own(data, field);
    if (values === undefined) continue;
    if (!object(values)) throw new ScanError(`Invalid ${field} map in npm metadata.`, 422);
    for (const [name, requested] of Object.entries(values)) {
      if (!packageName(name) || typeof requested !== 'string' || requested.length > 2048) throw new ScanError(`Invalid dependency declaration in ${field}.`, 422);
      if (kind === 'runtime' && object(data.optionalDependencies) && Object.hasOwn(data.optionalDependencies, name)) continue;
      const peerMeta = kind === 'peer' && object(data.peerDependenciesMeta) ? data.peerDependenciesMeta[name] : undefined;
      const optionalPeer = object(peerMeta) && peerMeta.optional === true;
      output.push({ name, requested, kind, ...(optionalPeer ? { optionalPeer: true } : {}) });
    }
  }
  return output;
}

/** Parse lockfiles as data only. Node resolution uses installation locations, never name-only lookup. */
export function parseDependencies(documents: NpmDocument[]): DependencyGraph {
  const graph: DependencyGraph = { nodes: [], edges: [], roots: [], unresolved: [], warnings: [] };
  const documentsByPath = new Map<string, ObjectValue>();
  for (const document of documents) {
    if (!object(document.data)) throw new ScanError(`Invalid npm metadata in ${document.path}.`, 422);
    documentsByPath.set(document.path, document.data);
  }
  const warn = (message: string) => {
    if (graph.warnings.length < 1000 && !graph.warnings.includes(message)) graph.warnings.push(message);
  };
  const consumedManifests = new Set<string>();
  const addNode = (context: string, installPath: string, data: ObjectValue, fallbackName: string, isProject: boolean): DependencyNode => {
    if (graph.nodes.length >= 10_000) throw new ScanError('Dependency graph exceeds 10,000 components.', 413);
    const rawVersion = text(data.version);
    const alias = rawVersion && /^npm:((?:@[^/]+\/)?[^@]+)@(.+)$/.exec(rawVersion);
    let version = alias ? alias[2] : rawVersion;
    if (data.version !== undefined && !version) throw new ScanError('Invalid package version.', 422);
    const name = text(data.name) ?? (alias ? alias[1] : fallbackName);
    if (name.length > 214 || (data.name !== undefined && !text(data.name))) throw new ScanError('Invalid package name.', 422);
    if (!isProject && version && !semver.valid(version)) {
      warn(`No exact semantic version for ${context}:${installPath}; lock value is not used as a resolved version.`);
      version = undefined;
    }
    const node: DependencyNode = { id: ref(context, installPath), name, ...(version ? { version } : {}), installPath, project: context, isProject, direct: false, transitive: false };
    if (!isProject) {
      if (typeof data.integrity === 'string') node.integrity = data.integrity.slice(0, 2000);
      if (typeof data.resolved === 'string') {
        try { const url = new URL(data.resolved); if (url.protocol === 'https:' && !url.username && !url.password) node.resolved = url.href.slice(0, 2000); } catch { /* Non-URL lock sources are not exposed. */ }
      }
    }
    graph.nodes.push(node);
    if (isProject) graph.roots.push(node.id);
    else if (!version) warn(`No resolved version for ${context}:${installPath}.`);
    return node;
  };
  const connect = (node: DependencyNode, declaration: ReturnType<typeof declarations>[number], target?: DependencyNode) => {
    if (graph.edges.length + graph.unresolved.length >= 50_000) throw new ScanError('Dependency graph exceeds 50,000 relationships.', 413);
    const { name, requested, kind } = declaration;
    if (!target) {
      graph.unresolved.push({ from: node.id, name, requested, kind, ...(declaration.optionalPeer ? { optionalPeer: true } : {}) });
      warn(declaration.optionalPeer ? `Optional peer dependency ${name} (${requested}) is not installed; optional by declaration in ${node.project}:${node.installPath || '<root>'}.` : `Unresolved ${kind} dependency ${name} (${requested}) from ${node.project}:${node.installPath || '<root>'}.`);
      return;
    }
    graph.edges.push({ from: node.id, to: target.id, name, requested, kind, ...(declaration.optionalPeer ? { optionalPeer: true } : {}) });
    if (node.isProject) target.direct = true;
    if (target.version && semver.valid(target.version) && semver.validRange(requested) && !semver.satisfies(target.version, requested)) warn(`Locked version ${target.name}@${target.version} does not satisfy ${name}@${requested} from ${node.project}:${node.installPath || '<root>'}.`);
  };

  // Process shallower locks first so workspace manifests can be associated with their enclosing lock.
  const locks = documents.filter(d => /(?:^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(d.path)).sort((a, b) => a.path.split('/').length - b.path.split('/').length || a.path.localeCompare(b.path));
  for (const document of locks) {
    const directory = posix.dirname(document.path) === '.' ? '' : posix.dirname(document.path);
    const at = (path: string) => directory ? `${directory}/${path}` : path;
    if (posix.basename(document.path) === 'package-lock.json' && documentsByPath.has(at('npm-shrinkwrap.json'))) {
      warn(`Ignored ${document.path}; npm-shrinkwrap.json takes precedence.`); continue;
    }
    const lock = documentsByPath.get(document.path)!;
    const manifestPath = at('package.json');
    const manifest = documentsByPath.get(manifestPath);
    if (!manifest) { warn(`No sibling package.json for ${document.path}; lock root metadata is used.`); }
    else consumedManifests.add(manifestPath);
    if (![1, 2, 3].includes(lock.lockfileVersion as number)) throw new ScanError(`Unsupported or missing lockfileVersion in ${document.path}.`, 422);
    const entries = new Map<string, ObjectValue>();
    const legacy = lock.lockfileVersion === 1;
    if (legacy) {
      const pending: { value: unknown; parent: string; depth: number }[] = [{ value: lock.dependencies ?? {}, parent: '', depth: 0 }];
      while (pending.length) {
        const item = pending.pop()!;
        if (!object(item.value) || item.depth > 100) throw new ScanError('Invalid or excessively nested v1 lockfile.', 422);
        for (const [name, data] of Object.entries(item.value)) {
          if (!packageName(name) || !object(data)) throw new ScanError('Invalid v1 lockfile dependency.', 422);
          const path = `${item.parent ? `${item.parent}/` : ''}node_modules/${name}`;
          if (entries.size >= 10_000 || !safePath(path)) throw new ScanError('Lockfile component limit or path limit exceeded.', 413);
          entries.set(path, data);
          if (data.dependencies !== undefined) pending.push({ value: data.dependencies, parent: path, depth: item.depth + 1 });
        }
      }
      entries.set('', manifest ?? { name: lock.name, version: lock.version });
    } else {
      if (!object(lock.packages)) throw new ScanError(`Missing packages map in ${document.path}.`, 422);
      for (const [path, data] of Object.entries(lock.packages)) {
        if (entries.size >= 10_000) throw new ScanError('Lockfile exceeds 10,000 entries.', 413);
        if ((path !== '' && !safePath(path)) || !object(data)) throw new ScanError(`Invalid packages entry in ${document.path}.`, 422);
        entries.set(path, data);
      }
      if (!entries.has('')) { warn(`Missing root entry in ${document.path}.`); entries.set('', manifest ?? lock); }
    }
    const nodes = new Map<string, DependencyNode>();
    const metadata = new Map<string, ObjectValue>();
    for (const [path, entry] of entries) {
      if (entry.link === true) continue;
      const isProject = path === '' || !path.split('/').includes('node_modules');
      const localManifestPath = at(path ? `${path}/package.json` : 'package.json');
      const localManifest = isProject ? documentsByPath.get(localManifestPath) : undefined;
      if (localManifest) consumedManifests.add(localManifestPath);
      const data = localManifest ?? entry;
      const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(path);
      if (!isProject && (!match || !packageName(match[1]))) throw new ScanError(`Invalid installation path ${path}.`, 422);
      const fallback = match?.[1] ?? text(lock.name) ?? (path || directory || 'unnamed-project');
      nodes.set(path, addNode(document.path, path, data, fallback, isProject));
      metadata.set(path, data);
    }
    const dereference = (path: string): { node: DependencyNode; path: string } | undefined => {
      const visited = new Set<string>();
      while (entries.get(path)?.link === true) {
        if (visited.size >= 100) { warn(`Workspace link chain exceeds 100 hops at ${document.path}:${path}.`); return; }
        if (visited.has(path)) { warn(`Cyclic workspace link at ${document.path}:${path}.`); return; }
        visited.add(path);
        const target = text(entries.get(path)!.resolved);
        if (!target || !safePath(target)) { warn(`Unsupported workspace link at ${document.path}:${path}.`); return; }
        path = target;
      }
      const node = nodes.get(path);
      if (node) return { node, path };
      if (visited.size) warn(`Missing workspace link target ${document.path}:${path}.`);
    };
    const lookup = (from: string, name: string, peer: boolean) => {
      let directory = peer && from.includes('node_modules') ? posix.dirname(from) : from;
      for (;;) {
        if (posix.basename(directory) !== 'node_modules') {
          const target = dereference(`${directory ? `${directory}/` : ''}node_modules/${name}`);
          if (target) return target.node;
        }
        if (!directory) break;
        const parent = posix.dirname(directory);
        directory = parent === '.' ? '' : parent;
      }
      return undefined;
    };
    for (const [path, node] of nodes) {
      const data = metadata.get(path)!;
      const declared = declarations(data, node.isProject, legacy && !node.isProject);
      // A v1 nested dependency is a real relationship even when old metadata omits requires.
      if (legacy && !node.isProject && object(data.dependencies)) {
        for (const [name, child] of Object.entries(data.dependencies)) {
          if (!declared.some(d => d.name === name)) declared.push({ name, requested: object(child) ? text(child.version) ?? '*' : '*', kind: 'runtime' });
        }
      }
      for (const declaration of declared) connect(node, declaration, lookup(path, declaration.name, declaration.kind === 'peer'));
    }
    // Link entries themselves are locations, not separate components.
    for (const [path, entry] of entries) if (entry.link === true) dereference(path);
  }

  for (const [path, manifest] of documentsByPath) {
    if (!/(?:^|\/)package\.json$/.test(path) || consumedManifests.has(path)) continue;
    const node = addNode(path, '', manifest, posix.dirname(path) === '.' ? 'unnamed-project' : posix.basename(posix.dirname(path)), true);
    warn(`No lockfile for ${path}; dependency ranges are not resolved versions.`);
    for (const declaration of declarations(manifest, true)) connect(node, declaration);
  }
  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges) { const children = adjacency.get(edge.from) ?? []; children.push(edge.to); adjacency.set(edge.from, children); }
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const queue = graph.roots.map(id => ({ id, depth: 0 }));
  const visited = new Set<string>();
  for (let i = 0; i < queue.length; i++) {
    const { id, depth } = queue[i];
    const key = `${id}:${depth}`;
    if (visited.has(key)) continue;
    visited.add(key);
    if (depth === 2) nodes.get(id)!.transitive = true;
    for (const child of adjacency.get(id) ?? []) queue.push({ id: child, depth: Math.min(2, depth + 1) });
  }
  graph.nodes.sort((a, b) => a.id.localeCompare(b.id));
  graph.edges.sort((a, b) => `${a.from}:${a.name}:${a.kind}`.localeCompare(`${b.from}:${b.name}:${b.kind}`));
  return graph;
}
