import type { DependencyGraph, DependencyNode, InventoryCounts, VulnerabilityReport } from '@traceguard/shared';

export const identity = (node: DependencyNode) => JSON.stringify([node.ecosystem ?? 'npm', node.name]);
export function inventoryCounts(graph: DependencyGraph): InventoryCounts {
  const packages = graph.nodes.filter(n => !n.isProject);
  return { projectModules: new Set(graph.roots).size, uniquePackages: new Set(packages.map(identity)).size, uniquePackageVersions: new Set(packages.filter(n => n.version).map(n => JSON.stringify([identity(n), n.version]))).size,
    dependencyInstances: packages.length, directDependencies: packages.filter(n => n.direct).length, transitiveOnlyDependencies: packages.filter(n => n.transitive && !n.direct).length, unknownRelationships: packages.filter(n => !n.direct && !n.transitive).length, dependencyEdges: graph.edges.length, unresolvedDeclarations: graph.unresolved.length };
}
export function packagePurl(node: DependencyNode): string | undefined {
  if (!node.version || node.isProject || node.advisoryEligible === false) return;
  const ecosystem = node.ecosystem ?? 'npm';
  if (ecosystem === 'Maven') { const [group, artifact] = node.name.split(':'); return group && artifact ? `pkg:maven/${encodeURIComponent(group)}/${encodeURIComponent(artifact)}@${encodeURIComponent(node.version)}` : undefined; }
  return `pkg:${ecosystem === 'PyPI' ? 'pypi' : 'npm'}/${node.name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(node.version)}`;
}
/** Union OSV aliases without double-counting a GHSA and its PYSEC/CVE record. */
export function advisoryCounts(graph: DependencyGraph, report: VulnerabilityReport) {
  const libraries = new Set(graph.nodes.filter(n => !n.isProject).map(n => n.id));
  const checks = report.checks.filter(c => libraries.has(c.nodeId)); const ids = [...new Set(checks.flatMap(c => c.advisoryIds))].sort();
  const parent = new Map<string, string>();
  const find = (id: string): string => { let current = id; while (parent.has(current)) current = parent.get(current)!; return current; };
  for (const detail of Object.values(report.advisories ?? {})) if (detail.verification === 'verified' && ids.includes(detail.id)) for (const alias of detail.aliases) { const a = find(detail.id), b = find(alias); if (a !== b) parent.set(a, b); }
  return { affectedInstances: checks.filter(c => c.status === 'matched').length, uniqueAdvisoryIds: ids.length, uniqueIssuesByAliases: new Set(ids.map(find)).size, unknownInstances: checks.filter(c => c.status === 'unknown' || !c.complete).length };
}
