import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import type { DependencyGraph, ScanResult, ProjectCoverage, ScanFile } from '@traceguard/shared';
import { inventoryCounts, packagePurl } from './canonical.js';
export const SCANNER_VERSION = '0.2.0';
export const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  return JSON.stringify(value);
}
export function canonicalizeGraph(graph: DependencyGraph) {
  for (const node of graph.nodes) {
    node.ecosystem ??= 'npm'; node.sourceFile = node.project; node.projectPath = posix.dirname(node.project);
    node.parentIds = [...new Set(graph.edges.filter(e => e.to === node.id).map(e => e.from))].sort();
    node.declaredConstraints = [...new Set([...graph.edges.filter(e => e.to === node.id).map(e => e.requested), ...graph.unresolved.filter(e => e.from === node.id).map(e => e.requested)])].sort();
    node.resolutionConfidence = !node.version ? 'unresolved' : node.versionEvidence === 'exact-pin' || node.versionEvidence === 'manifest-exact' ? 'declared-exact' : 'recorded-lock';
    node.purl = packagePurl(node); node.limitations = !node.version ? ['Version unresolved; no exact-version advisory clearance.'] : node.resolutionConfidence === 'declared-exact' ? ['Declared exact version is not proof of a resolved or installed environment.'] : [];
  }
  graph.nodes.sort((a, b) => a.id.localeCompare(b.id)); graph.edges.sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
  graph.roots.sort(); graph.unresolved.sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))); graph.warnings = [...new Set(graph.warnings)].sort();
  return graph;
}
export const inventoryHash = (graph: DependencyGraph) => digest(canonicalJson(graph));
export const isOptionalPeerNotice = (warning: string) => warning.startsWith('Optional peer dependency ');

export function extraMetadata(name: string) {
  if (name === 'pom.xml' || name === 'gradle.lockfile' || name.endsWith('.lockfile')) return 'java';
  if (['build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'].includes(name)) return 'gradle-build';
  if (['Cargo.toml', 'Cargo.lock', 'go.mod', 'go.sum', 'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock', 'yarn.lock', 'pnpm-lock.yaml', 'uv.lock', 'Pipfile', 'Pipfile.lock', 'setup.py', 'setup.cfg', 'environment.yml', 'Package.swift', 'packages.lock.json'].includes(name) || name.endsWith('.csproj')) return 'unsupported';
}
export function projectCoverage(files: ScanFile[], graph: DependencyGraph): ProjectCoverage[] {
  const result: ProjectCoverage[] = [];
  for (const file of files) {
    const name = posix.basename(file.path); const path = posix.dirname(file.path);
    if (file.kind === 'source') {
      result.push({ path, manager: 'Unrecognized dependency format', status: 'unsupported', reasons: [`${file.path}: source was detected, but no supported dependency manifest or lockfile was found.`] }); continue;
    }
    let manager = file.ecosystem === 'PyPI' ? name === 'poetry.lock' ? 'Poetry' : 'Python' : file.ecosystem === 'Maven' ? name === 'pom.xml' ? 'Maven' : 'Gradle lock' : 'npm';
    const extra = extraMetadata(name);
    if (extra === 'unsupported') { result.push({ path, manager: name, status: 'unsupported', reasons: [`${file.path}: ecosystem/parser unsupported; no clean result is inferred.`] }); continue; }
    if (extra === 'gradle-build') {
      const locked = files.some(f => posix.dirname(f.path) === path && f.path.endsWith('.lockfile'));
      result.push({ path, manager: 'Gradle build', status: locked ? 'partial' : 'unknown', reasons: ['Gradle build scripts are executable code and are never evaluated; only supported lock records are parsed.'] }); continue;
    }
    const contextNodes = graph.nodes.filter(n => n.project === file.path || posix.dirname(n.project) === path && n.ecosystem === file.ecosystem);
    const reasons = graph.warnings.filter(w => w.includes(file.path) && !isOptionalPeerNotice(w)).slice(0, 30);
    const unresolved = contextNodes.some(n => !n.isProject && !n.version) || graph.unresolved.some(d => !d.optionalPeer && contextNodes.some(n => n.id === d.from));
    result.push({ path, manager, status: !contextNodes.some(n => !n.isProject) ? 'unknown' : reasons.length || unresolved ? 'partial' : 'analyzed', reasons: reasons.length ? reasons : unresolved ? ['Some versions or relationships are unresolved.'] : [] });
  }
  return result.sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
}
export function attachInventory(scan: ScanResult, archive: Buffer, languages: string[], revision?: { repositoryUrl: string; commitSha: string }) {
  scan.counts = inventoryCounts(scan.graph!); const projects = projectCoverage(scan.files, scan.graph!);
  const blockingWarnings = scan.graph!.warnings.filter(warning => !isOptionalPeerNotice(warning));
  scan.analysisStatus = projects.every(p => p.status === 'unsupported') ? 'unsupported' : !scan.counts.dependencyInstances ? 'unknown' : projects.some(p => p.status !== 'analyzed') || blockingWarnings.length ? 'partial' : 'analyzed';
  scan.evidence = { scannerVersion: SCANNER_VERSION, archiveSha256: digest(archive), ...revision, revisionStatus: revision ? 'pinned' : 'unknown', inventorySha256: inventoryHash(scan.graph!), languages: [...new Set(languages)].sort(), projects, metadataHashes: scan.files.map(f => ({ path: f.path, sha256: f.sha256! })).sort((a, b) => a.path.localeCompare(b.path)) };
}
