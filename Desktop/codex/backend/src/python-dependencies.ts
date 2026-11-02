import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { DependencyGraph, DependencyNode, DependencyKind } from '@traceguard/shared';
import { ScanError } from './errors.js';
import { exactVersion, normalizePythonName, pythonName, pythonSatisfies } from './ecosystems.js';

export interface PythonDocument { path: string; content: string }
type Obj = Record<string, unknown>;
const obj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
type Declaration = { name: string; spec: string; kind: DependencyKind; external?: boolean; conditional?: boolean };

/** Data-only, bounded metadata inventory. No pip/Poetry/PEP517 processes or environment evaluation. */
export function parsePythonDependencies(documents: PythonDocument[]): DependencyGraph {
  const graph: DependencyGraph = { nodes: [], roots: [], edges: [], unresolved: [], warnings: [] };
  const warn = (message: string) => { if (graph.warnings.length < 1000 && !graph.warnings.includes(message)) graph.warnings.push(message); };
  const groups = new Map<string, PythonDocument[]>();
  for (const document of documents) {
    const directory = posix.dirname(document.path);
    const group = groups.get(directory) ?? []; group.push(document); groups.set(directory, group);
  }
  const toml = (document: PythonDocument): Obj => {
    try { return parseToml(document.content, { maxDepth: 50 }) as Obj; }
    catch { throw new ScanError(`Invalid or excessively nested TOML in ${document.path}.`, 422); }
  };
  const named = (name: string) => { if (!pythonName(name)) throw new ScanError('Invalid Python distribution name.', 422); return normalizePythonName(name); };
  const requirement = (line: string, path: string, kind: DependencyKind): Declaration | undefined => {
    const value = line.trim();
    if (!value || value.startsWith('#')) return;
    if (/^(?:https?:|git\+|file:|\.{0,2}\/)/i.test(value)) { warn(`${path}: bare URL or local path is not a verified PyPI dependency; not fetched.`); return; }
    if (value.startsWith('-') || value.includes('${')) { warn(`${path}: unsupported requirements option/include/editable or environment substitution; not fetched or evaluated.`); return; }
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9_,. -]+\])?\s*(.*)$/.exec(value);
    if (!match) { warn(`${path}: unsupported dependency declaration; local paths and URLs are not fetched.`); return; }
    const name = named(match[1]); let spec = match[3].trim();
    const conditional = spec.includes(';') || !!match[2];
    spec = spec.split(';')[0].trim().replace(/^\((.*)\)$/, '$1').trim();
    const external = spec.startsWith('@') || /(?:https?:|git\+|file:|\/)/i.test(spec);
    if (conditional) warn(`${path}: markers/extras for ${name} are not evaluated; all recorded candidates are inventoried.`);
    if (external) warn(`${path}: external/local dependency ${name} has no verified PyPI identity or version.`);
    return { name, spec, kind, external, conditional };
  };
  for (const [directory, files] of groups) {
    const projectFile = files.find(f => posix.basename(f.path) === 'pyproject.toml');
    const lockFile = files.find(f => posix.basename(f.path) === 'poetry.lock');
    const requirementFiles = files.filter(f => /\.txt$/.test(f.path));
    const manifest = projectFile ? toml(projectFile) : {};
    if (manifest.project !== undefined && !obj(manifest.project) || manifest.tool !== undefined && !obj(manifest.tool)) throw new ScanError(`Invalid project/tool table in ${projectFile?.path}.`, 422);
    const project = obj(manifest.project) ? manifest.project : {};
    const tool = obj(manifest.tool) ? manifest.tool : {};
    if (tool.poetry !== undefined && !obj(tool.poetry)) throw new ScanError(`Invalid tool.poetry table in ${projectFile?.path}.`, 422);
    const poetry = obj(tool.poetry) ? tool.poetry : {};
    if (project['optional-dependencies'] !== undefined && !obj(project['optional-dependencies'])) throw new ScanError(`Invalid optional dependency table in ${projectFile?.path}.`, 422);
    const customSources = Array.isArray(poetry.source) && poetry.source.length > 0;
    if (customSources) warn(`${projectFile?.path}: Poetry source configuration is not independently verified; public PyPI identity remains UNKNOWN.`);
    const context = lockFile?.path ?? projectFile?.path ?? requirementFiles[0].path;
    const add = (name: string, version: string | undefined, location: string, isProject = false, eligible = true, pin = false) => {
      if (graph.nodes.length >= 10_000) throw new ScanError('Dependency graph exceeds 10,000 components.', 413);
      const publicIdentity = eligible && !customSources && !version?.includes('+');
      const node: DependencyNode = { id: `urn:traceguard:component:${createHash('sha256').update(`PyPI\0${context}\0${location}`).digest('hex')}`, ecosystem: 'PyPI', name, ...(version ? { version } : {}), project: context, installPath: location, isProject, direct: false, transitive: false, advisoryEligible: publicIdentity, ...(version && !isProject ? { versionEvidence: pin ? 'exact-pin' as const : 'lockfile' as const } : {}) };
      if (version?.includes('+')) warn(`${context}: local build ${name}@${version} has unverified public PyPI identity; advisory status is UNKNOWN.`);
      graph.nodes.push(node); return node;
    };
    const root = add(String(project.name ?? poetry.name ?? (directory === '.' ? 'python-project' : posix.basename(directory))).slice(0, 214), undefined, '', true);
    graph.roots.push(root.id);
    const declarations: Declaration[] = [];
    const addList = (value: unknown, kind: DependencyKind) => {
      if (value === undefined) return;
      if (!Array.isArray(value) || value.some(v => typeof v !== 'string')) throw new ScanError(`Invalid Python dependency list in ${context}.`, 422);
      for (const valueItem of value) { const entry = requirement(valueItem as string, context, kind); if (entry) declarations.push(entry); }
    };
    addList(project.dependencies, 'runtime');
    if (obj(project['optional-dependencies'])) { for (const value of Object.values(project['optional-dependencies'])) addList(value, 'optional'); warn(`${context}: optional groups are inventoried without selecting extras.`); }
    if (Array.isArray(project.dynamic) && project.dynamic.includes('dependencies')) warn(`${context}: dynamic dependencies cannot be resolved without executing a build backend; not executed.`);
    if (obj(manifest['dependency-groups'])) {
      for (const value of Object.values(manifest['dependency-groups'])) {
        if (!Array.isArray(value)) throw new ScanError(`Invalid dependency group in ${context}.`, 422);
        addList(value.filter(v => typeof v === 'string'), 'dev');
        if (value.some(v => typeof v !== 'string')) warn(`${context}: dependency-group includes are not expanded.`);
      }
    }
    const poetryDeclarations = (value: unknown, kind: DependencyKind, target: Declaration[]) => {
      if (value === undefined) return;
      if (!obj(value)) throw new ScanError(`Invalid Poetry dependency map in ${context}.`, 422);
      for (const [rawName, raw] of Object.entries(value)) {
        if (rawName.toLowerCase() === 'python') continue;
        const name = named(rawName);
        for (const item of Array.isArray(raw) ? raw : [raw]) {
          if (typeof item !== 'string' && !obj(item)) throw new ScanError(`Invalid Poetry dependency ${name}.`, 422);
          if (obj(item) && item.version !== undefined && typeof item.version !== 'string') throw new ScanError(`Invalid Poetry version constraint for ${name}.`, 422);
          const spec = typeof item === 'string' ? item : typeof item.version === 'string' ? item.version : '*';
          const external = obj(item) && ['git', 'path', 'url', 'source'].some(k => item[k] !== undefined);
          if (external) warn(`${context}: external/custom source for ${name} is not resolved or queried as PyPI.`);
          if (obj(item) && ['markers', 'python', 'platform', 'extras', 'optional'].some(k => item[k] !== undefined)) warn(`${context}: conditional Poetry dependency ${name}; markers/extras are not evaluated.`);
          target.push({ name, spec, kind, external });
        }
      }
    };
    // Poetry can enrich PEP 621 declarations with source identity. Keep both: no source is silently ignored.
    poetryDeclarations(poetry.dependencies, 'runtime', declarations);
    poetryDeclarations(poetry['dev-dependencies'], 'dev', declarations);
    if (obj(poetry.group)) for (const group of Object.values(poetry.group)) if (obj(group)) poetryDeclarations(group.dependencies, 'dev', declarations);
    const byName = new Map<string, DependencyNode[]>();
    const edgeKeys = new Set<string>();
    const remember = (node: DependencyNode) => { const values = byName.get(node.name) ?? []; values.push(node); byName.set(node.name, values); };
    const unresolved = (from: DependencyNode, declaration: Declaration) => {
      if (graph.edges.length + graph.unresolved.length >= 50_000) throw new ScanError('Dependency graph exceeds 50,000 relationships.', 413);
      graph.unresolved.push({ from: from.id, name: declaration.name, requested: declaration.spec, kind: declaration.kind });
      warn(`${context}: unresolved or ambiguous ${declaration.name} (${declaration.spec}); no version or relationship is guessed.`);
    };
    const connect = (from: DependencyNode, declaration: Declaration) => {
      if (graph.edges.length + graph.unresolved.length >= 50_000) throw new ScanError('Dependency graph exceeds 50,000 relationships.', 413);
      const matches = declaration.external ? [] : (byName.get(declaration.name) ?? []).filter(n => n.version && pythonSatisfies(n.version, declaration.spec) === true);
      if (matches.length !== 1) { unresolved(from, declaration); return; }
      const target = matches[0];
      const key = JSON.stringify([from.id, target.id, declaration.kind]);
      if (!edgeKeys.has(key)) { edgeKeys.add(key); graph.edges.push({ from: from.id, to: target.id, name: target.name, requested: declaration.spec, kind: declaration.kind }); }
      if (from.isProject) target.direct = true;
    };
    if (lockFile) {
      const lock = toml(lockFile);
      if (!obj(lock.metadata) || typeof lock.metadata['lock-version'] !== 'string' || !/^[12]\.\d+$/.test(lock.metadata['lock-version']) || !Array.isArray(lock.package)) throw new ScanError(`Unsupported or malformed Poetry lockfile ${lockFile.path}.`, 422);
      warn(`${lockFile.path}: inventory is a lock snapshot; Python/platform activation, artifact hashes and lockfile freshness are not independently verified.`);
      const records: { node: DependencyNode; data: Obj }[] = [];
      for (const [index, pkg] of lock.package.entries()) {
        if (!obj(pkg) || typeof pkg.name !== 'string' || typeof pkg.version !== 'string' || !exactVersion('PyPI', pkg.version)) throw new ScanError(`Invalid Poetry package in ${lockFile.path}.`, 422);
        const eligible = pkg.source === undefined && !declarations.some(d => d.name === named(pkg.name as string) && d.external);
        const node = add(named(pkg.name), pkg.version, `poetry/${named(pkg.name)}@${pkg.version}#${index}`, false, eligible);
        remember(node); records.push({ node, data: pkg });
        if (!eligible) warn(`${lockFile.path}: ${node.name} uses an external/custom source; PyPI identity is unknown.`);
        if (pkg.markers !== undefined || pkg.optional === true) warn(`${lockFile.path}: conditional packages are included; marker/extras activation is not evaluated.`);
      }
      for (const { node, data } of records) { const children: Declaration[] = []; poetryDeclarations(data.dependencies, 'runtime', children); for (const child of children) connect(node, child); }
      for (const declaration of declarations) connect(root, declaration);
      if (!projectFile) warn(`${lockFile.path}: no sibling pyproject.toml; direct versus transitive classification is UNKNOWN.`);
      if (requirementFiles.length) {
        warn(`${context}: sibling requirements files are scanned as a separate inventory, not substituted for the Poetry lock.`);
        const extra = parsePythonDependencies(requirementFiles);
        graph.nodes.push(...extra.nodes); graph.roots.push(...extra.roots); graph.edges.push(...extra.edges); graph.unresolved.push(...extra.unresolved); for (const message of extra.warnings) warn(message);
      }
    } else {
      for (const file of requirementFiles) {
        const lines = file.content.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
        if (lines.length > 20_000) throw new ScanError('Requirements file exceeds 20,000 lines.', 413);
        const customIndex = lines.some(line => /^\s*(?:--(?:extra-)?index-url\b|--no-index\b|-i(?:\s|=))/.test(line));
        if (customIndex) warn(`${file.path}: custom/index configuration prevents verification of public PyPI identity; lookups remain UNKNOWN.`);
        for (const [index, raw] of lines.entries()) {
          const entry = requirement(raw.replace(/\s+#.*$/, '').replace(/\s+--hash=[^\s]+/g, '').trim(), file.path, 'runtime');
          if (!entry) continue;
          const pin = /^==\s*([^*,\s]+)$/.exec(entry.spec);
          const version = !entry.external && pin && exactVersion('PyPI', pin[1]) ? pin[1] : undefined;
          remember(add(entry.name, version || undefined, `${posix.basename(file.path)}:${index + 1}:${entry.name}`, false, !entry.external && !customIndex, true));
          if (!version) warn(`${file.path}: ${entry.name} has no exact resolved version; advisory status is UNKNOWN.`);
        }
      }
      for (const declaration of declarations) {
        if (!(byName.get(declaration.name)?.length)) {
          const pin = /^(?:==|===)\s*([^*,\s]+)$/.exec(declaration.spec);
          const version = !declaration.external && pin && exactVersion('PyPI', pin[1]) ? pin[1] : undefined;
          const node = add(declaration.name, version || undefined, `declared/${declaration.name}`, false, !declaration.external, true); remember(node);
          if (!version) { node.direct = true; graph.edges.push({ from: root.id, to: node.id, name: node.name, requested: declaration.spec, kind: declaration.kind }); }
        }
        connect(root, declaration);
      }
      warn(`${context}: no Poetry lock; exact pins are recorded specifications, not proof of installed versions. Transitive dependency metadata is incomplete.`);
    }
    // Classification follows only real, unambiguous paths from declared project dependencies.
    const adjacency = new Map<string, string[]>(); const byId = new Map(graph.nodes.map(n => [n.id, n]));
    for (const edge of graph.edges) { const values = adjacency.get(edge.from) ?? []; values.push(edge.to); adjacency.set(edge.from, values); }
    const queue = (adjacency.get(root.id) ?? []).map(id => ({ id, depth: 1 })); const visited = new Set<string>();
    for (let i = 0; i < queue.length; i++) {
      const { id, depth } = queue[i]; const key = `${id}:${depth}`; if (visited.has(key)) continue; visited.add(key);
      const node = byId.get(id)!; if (depth >= 2) node.transitive = true;
      for (const child of adjacency.get(id) ?? []) queue.push({ id: child, depth: 2 });
    }
    if (graph.nodes.some(n => n.project === context && !n.isProject && !n.direct && !n.transitive)) warn(`${context}: some package relationships are UNKNOWN; unconnected lock entries/pins are not assumed direct or transitive.`);
  }
  if (graph.nodes.length > 10_000 || graph.edges.length + graph.unresolved.length > 50_000) throw new ScanError('Python inventory exceeds graph limits.', 413);
  return graph;
}
