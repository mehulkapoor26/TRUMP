import { createHash, randomUUID } from 'node:crypto';
import type { ScanResult, ScanComparison, VulnerabilityReport, DependencyNode } from '@traceguard/shared';
import { ScanError } from './errors.js';
import { checkVulnerabilities } from './vulnerabilities.js';
import { ecosystemOf } from './ecosystems.js';

export function compareEvidence(before: ScanResult, after: ScanResult, beforeChecks: VulnerabilityReport, afterChecks: VulnerabilityReport): ScanComparison {
  if (!before.graph || !after.graph) throw new ScanError('Both scans need dependency inventories. Rescan older records.', 409);
  if (before.id === after.id) throw new ScanError('Choose two distinct scans.');
  const a = before.graph.nodes.filter(n => !n.isProject), b = after.graph.nodes.filter(n => !n.isProject);
  const checksA = new Map(beforeChecks.checks.map(c => [c.nodeId, c]));
  const checksB = new Map(afterChecks.checks.map(c => [c.nodeId, c]));
  const inventoryComplete = (scan: ScanResult) => !!scan.graph && !scan.graph.warnings.length && !scan.graph.unresolved.length && scan.graph.roots.length > 0;
  const completeFor = (name: string, ecosystem: string, scan: ScanResult, nodes: DependencyNode[], checks: typeof checksA) => inventoryComplete(scan) && nodes.filter(n => n.name === name && ecosystemOf(n) === ecosystem).every(n => !!n.version && checks.get(n.id)?.complete === true && checks.get(n.id)?.status !== 'unknown');
  const entries = new Map<string, { name: string; id: string; ecosystem: string }>();
  for (const [nodes, checks] of [[a, checksA], [b, checksB]] as const) for (const node of nodes) for (const id of checks.get(node.id)?.advisoryIds ?? []) entries.set(JSON.stringify([ecosystemOf(node), node.name, id]), { name: node.name, id, ecosystem: ecosystemOf(node) });
  const instances = (nodes: DependencyNode[], checks?: typeof checksA, advisory?: string) => nodes.map(({ id: nodeId, version, installPath, project }) => ({ nodeId, version, installPath, project, ...(checks && advisory ? { advisoryMatched: checks.get(nodeId)?.advisoryIds.includes(advisory) ?? false } : {}) }));
  const issues: ScanComparison['issues'] = [];
  for (const { name, id, ecosystem } of entries.values()) {
    const old = a.filter(n => n.name === name && ecosystemOf(n) === ecosystem && checksA.get(n.id)?.advisoryIds.includes(id));
    const updated = b.filter(n => n.name === name && ecosystemOf(n) === ecosystem && checksB.get(n.id)?.advisoryIds.includes(id));
    const status = old.length && updated.length ? 'remaining' : old.length ? completeFor(name, ecosystem, after, b, checksB) ? 'resolved' : 'unverifiable' : completeFor(name, ecosystem, before, a, checksA) ? 'newlyIntroduced' : 'unverifiable';
    issues.push({ packageName: name, ecosystem: ecosystem as 'npm' | 'PyPI', advisoryId: id, status, before: instances(a.filter(n => n.name === name && ecosystemOf(n) === ecosystem), checksA, id), after: instances(b.filter(n => n.name === name && ecosystemOf(n) === ecosystem), checksB, id), reason: status === 'remaining' ? 'The same package/advisory ID is observed in both inventories; affected instance counts may differ.' : status === 'resolved' ? 'No matching advisory ID remains for this package in the after inventory, with complete relevant version checks and no inventory gaps. This includes package removal.' : status === 'newlyIntroduced' ? 'This advisory ID is observed after and absent before, with complete relevant baseline checks and no baseline inventory gaps.' : 'The opposite inventory or relevant advisory checks are incomplete. Absence cannot establish resolution or introduction.' });
  }
  const unknownNames = new Set([...a.filter(n => !checksA.get(n.id)?.complete || checksA.get(n.id)?.status === 'unknown'), ...b.filter(n => !checksB.get(n.id)?.complete || checksB.get(n.id)?.status === 'unknown')].map(n => JSON.stringify([ecosystemOf(n), n.name])));
  for (const key of unknownNames) { const [ecosystem, name] = JSON.parse(key); issues.push({ packageName: name, status: 'unverifiable', before: instances(a.filter(n => n.name === name && ecosystemOf(n) === ecosystem)), after: instances(b.filter(n => n.name === name && ecosystemOf(n) === ecosystem)), reason: 'At least one package instance has unknown, missing, or paginated advisory coverage. Additional issues may be unobserved.' }); }
  if (!inventoryComplete(before) || !inventoryComplete(after)) issues.push({ packageName: '(inventory coverage)', status: 'unverifiable', before: [], after: [], reason: 'An inventory has warnings, unresolved declarations, or no project roots. Missing packages and issues cannot be ruled out.' });
  const snapshot = (scan: ScanResult, checks: VulnerabilityReport) => ({ scanId: scan.id, createdAt: scan.createdAt, source: scan.source, inventorySha256: createHash('sha256').update(JSON.stringify(scan.graph)).digest('hex'), advisoryCheckedAt: checks.checkedAt, inventoryWarnings: scan.graph?.warnings ?? [], unresolvedDependencies: scan.graph?.unresolved.length ?? 0 });
  return { id: randomUUID(), generatedAt: new Date().toISOString(), before: snapshot(before, beforeChecks), after: snapshot(after, afterChecks), issues, counts: { resolved: issues.filter(i => i.status === 'resolved').length, remaining: issues.filter(i => i.status === 'remaining').length, newlyIntroduced: issues.filter(i => i.status === 'newlyIntroduced').length, unverifiable: issues.filter(i => i.status === 'unverifiable').length }, beforeChecks, afterChecks,
    limitations: ['Both saved inventories are checked against current OSV data during comparison. This is not a comparison of historical advisory database states or proof that a code change caused an outcome.', 'Issues are grouped by ecosystem, exact package name and advisory ID across all instances. Versions and paths are retained as evidence, but duplicate instances are not paired by installation path. Advisory aliases are not deduplicated; an ID change can appear as resolved and introduced.', 'Resolved means no longer observed under complete relevant checks and inventory coverage, including dependency removal. It does not prove safe execution or validate the fix. Remaining may include fewer affected instances.', 'Newly introduced means newly observed in the after inventory against current advisory data; it does not establish when a vulnerability was created.', 'Unverifiable includes coverage gaps as well as issues whose absence cannot be established. Counts include coverage rows and are not counts of unique exploitable vulnerabilities.', 'The user declares that these inventories represent the same project. Repository identity, commit lineage, deployment identity, source completeness, runtime exploitability and compatibility are not verified.', 'No user code, manifests or lockfiles are modified and no submitted install scripts or source code are executed. Suspicious package heuristics are separate from this vulnerability comparison.'] };
}
export async function compareScans(before: ScanResult, after: ScanResult, fetcher: typeof fetch = fetch) {
  if (!before.graph || !after.graph) throw new ScanError('Both scans need dependency inventories.', 409);
  if (before.id === after.id) throw new ScanError('Choose two distinct scans.');
  // One batched query deduplicates identical versions across both inventories.
  const graph = { nodes: [...before.graph.nodes.map(n => ({ ...n, id: `before:${n.id}` })), ...after.graph.nodes.map(n => ({ ...n, id: `after:${n.id}` }))], edges: [], roots: [], unresolved: [], warnings: [] };
  const result = await checkVulnerabilities(graph, fetcher);
  const scoped = (prefix: string): VulnerabilityReport => {
    const checks = result.checks.filter(c => c.nodeId.startsWith(prefix)).map(c => ({ ...c, nodeId: c.nodeId.slice(prefix.length) }));
    const libraries = graph.nodes.filter(n => !n.isProject && n.id.startsWith(prefix));
    const relevant = checks.filter(c => libraries.some(n => n.id === `${prefix}${c.nodeId}`));
    const status = relevant.length && relevant.every(c => c.complete) ? 'complete' : relevant.some(c => c.complete || c.status === 'matched') ? 'partial' : 'unavailable';
    return { ...result, status, checks };
  };
  return compareEvidence(before, after, scoped('before:'), scoped('after:'));
}
