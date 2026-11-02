import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import type { DependencyGraph, DependencyNode, DependencyKind } from '@traceguard/shared';
import { ScanError } from './errors.js';

export interface JavaDocument { path: string; content: string }
type Obj = Record<string, any>;
const object = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const list = (v: any): any[] => v === undefined ? [] : Array.isArray(v) ? v : [v];
const coordinate = (s: string) => /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/.test(s) && s.length <= 300;
export const mavenExact = (v: string) => v.length <= 200 && /^[0-9][A-Za-z0-9_.-]*$/.test(v) && !/SNAPSHOT|LATEST|RELEASE/i.test(v);

/** Static POM declarations and Gradle lock records only; never invoke a JVM/build tool. */
export function parseJavaDependencies(documents: JavaDocument[]): DependencyGraph {
  const graph: DependencyGraph = { nodes: [], edges: [], roots: [], unresolved: [], warnings: [] };
  const warn = (s: string) => { if (!graph.warnings.includes(s) && graph.warnings.length < 1000) graph.warnings.push(s); };
  const poms = new Map<string, Obj>();
  for (const doc of documents.filter(d => posix.basename(d.path) === 'pom.xml')) {
    if (/<!DOCTYPE|<!ENTITY/i.test(doc.content)) throw new ScanError(`DTD/entities are unsupported in ${doc.path}.`, 422);
    if (XMLValidator.validate(doc.content) !== true || (doc.content.match(/</g)?.length ?? 0) > 50_000) throw new ScanError(`Invalid or oversized Maven XML structure in ${doc.path}.`, 422);
    let depth = 0; for (const token of doc.content.match(/<[^>]*>/g) ?? []) { if (/^<\//.test(token)) depth--; else if (!/^<[!?]/.test(token) && !/\/>$/.test(token)) depth++; if (depth > 50) throw new ScanError('Maven XML nesting exceeds 50.', 413); }
    const parsed = new XMLParser({ ignoreAttributes: true, removeNSPrefix: true, parseTagValue: false, processEntities: false }).parse(doc.content);
    if (!object(parsed.project)) throw new ScanError(`Missing Maven project in ${doc.path}.`, 422); poms.set(doc.path, parsed.project);
  }
  const add = (path: string, name: string, version: string | undefined, location: string, isProject: boolean, locked = false): DependencyNode => {
    if (graph.nodes.length >= 10_000) throw new ScanError('Java inventory component limit exceeded.', 413);
    const node: DependencyNode = { id: `urn:traceguard:component:${createHash('sha256').update(`Maven\0${path}\0${location}`).digest('hex')}`, ecosystem: 'Maven', name, ...(version ? { version } : {}), project: path, installPath: location, isProject, direct: false, transitive: false, versionEvidence: locked ? 'lockfile' : 'manifest-exact' };
    graph.nodes.push(node); if (isProject) graph.roots.push(node.id); return node;
  };
  const effective = (path: string, visited = new Set<string>()): { properties: Obj; managed: Map<string, string>; group: string; version: string } => {
    const pom = poms.get(path)!; const own = { properties: object(pom.properties) ? pom.properties : {}, managed: new Map<string, string>(), group: String(pom.groupId ?? pom.parent?.groupId ?? ''), version: String(pom.version ?? pom.parent?.version ?? '') };
    if (visited.has(path) || visited.size >= 10) { warn(`${path}: parent cycle/depth is unresolved.`); return own; } visited.add(path);
    let base = own;
    if (object(pom.parent)) {
      const relative = typeof pom.parent.relativePath === 'string' ? pom.parent.relativePath : '../pom.xml';
      const parentPath = posix.normalize(posix.join(posix.dirname(path), relative));
      const parent = !parentPath.startsWith('../') && poms.get(parentPath);
      if (parent && String(parent.artifactId) === String(pom.parent.artifactId) && String(parent.groupId ?? parent.parent?.groupId) === String(pom.parent.groupId) && String(parent.version ?? parent.parent?.version) === String(pom.parent.version)) base = effective(parentPath, visited);
      else warn(`${path}: parent POM not resolved from matching local metadata; no remote parent is fetched.`);
    }
    const properties: Obj = { ...base.properties, ...own.properties, 'project.groupId': own.group, 'project.version': own.version, 'pom.groupId': own.group, 'pom.version': own.version };
    const expand = (input: unknown) => { let value = typeof input === 'string' ? input : ''; for (let i = 0; i < 10; i++) { const next = value.replace(/\$\{([^}]+)\}/g, (whole, key) => typeof properties[key] === 'string' ? properties[key] : whole); if (next === value) break; value = next; } return value; };
    const managed = new Map(base.managed);
    for (const dep of list(pom.dependencyManagement?.dependencies?.dependency)) {
      if (!object(dep)) continue; const name = `${expand(dep.groupId)}:${expand(dep.artifactId)}`;
      if (dep.scope === 'import' || dep.type === 'pom') { warn(`${path}: imported BOM ${name} is not fetched; managed versions may be unresolved.`); continue; }
      if (coordinate(name)) managed.set(name, expand(dep.version));
    }
    return { properties, managed, group: own.group, version: own.version };
  };
  for (const [path, pom] of poms) {
    const meta = effective(path); const root = add(path, `${meta.group || 'unknown'}:${String(pom.artifactId ?? 'module')}`, undefined, '', true);
    const expand = (input: unknown) => { let value = typeof input === 'string' ? input : ''; for (let i = 0; i < 10; i++) { const next = value.replace(/\$\{([^}]+)\}/g, (whole, key) => typeof meta.properties[key] === 'string' ? meta.properties[key] : whole); if (next === value) break; value = next; } return value; };
    warn(`${path}: Maven declarations are not an effective resolved tree. Transitive dependencies, profiles, exclusions, conflict mediation and runtime installation are not resolved; Maven is never executed.`);
    if (pom.profiles) warn(`${path}: profile dependencies are not activated or merged.`);
    for (const [index, dep] of list(pom.dependencies?.dependency).entries()) {
      if (!object(dep)) throw new ScanError(`Invalid Maven dependency in ${path}.`, 422);
      const name = `${expand(dep.groupId)}:${expand(dep.artifactId)}`; const requested = expand(dep.version) || meta.managed.get(name) || '';
      if (!coordinate(name)) { graph.unresolved.push({ from: root.id, name, requested, kind: 'runtime' }); warn(`${path}: unresolved Maven coordinate.`); continue; }
      const version = mavenExact(requested) ? requested : undefined;
      const kind: DependencyKind = dep.scope === 'test' ? 'dev' : dep.optional === 'true' || dep.scope === 'provided' ? 'optional' : 'runtime';
      const node = add(path, name, version, `dependency:${index}:${name}`, false); node.direct = true;
      graph.edges.push({ from: root.id, to: node.id, name, requested, kind });
      if (!version) { graph.unresolved.push({ from: root.id, name, requested, kind }); warn(`${path}: version for ${name} is unresolved; no range/property is guessed.`); }
      if (graph.edges.length + graph.unresolved.length > 50_000) throw new ScanError('Java relationship limit exceeded.', 413);
    }
  }
  for (const doc of documents.filter(d => d.path.endsWith('.lockfile'))) {
    add(doc.path, `Gradle lock ${posix.dirname(doc.path)}`, undefined, '', true);
    warn(`${doc.path}: Gradle lock versions are recorded, but lockfiles do not establish direct/transitive edges or active configurations. Build scripts are never executed.`);
    const lines = doc.content.split(/\r?\n/); if (lines.length > 20_000) throw new ScanError('Gradle lock line limit exceeded.', 413);
    for (const [index, line] of lines.entries()) {
      const value = line.trim(); if (!value || value.startsWith('#') || value.startsWith('empty=')) continue;
      const match = /^([^:=\s]+):([^:=\s]+):([^=\s]+)(?:=.*)?$/.exec(value);
      if (!match || !coordinate(`${match[1]}:${match[2]}`) || !mavenExact(match[3])) { warn(`${doc.path}: unsupported/malformed lock record at line ${index + 1}.`); continue; }
      add(doc.path, `${match[1]}:${match[2]}`, match[3], `line:${index + 1}`, false, true);
    }
  }
  return graph;
}
