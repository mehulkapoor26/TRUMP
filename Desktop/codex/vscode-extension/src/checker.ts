import { parseDependencies } from '../../backend/src/dependencies';
import { checkVulnerabilities } from '../../backend/src/vulnerabilities';
import { inventoryCounts, advisoryCounts } from '../../backend/src/canonical';

export interface MetadataFile { path: string; content: string }
export interface Finding { path: string; offset: number; length: number; message: string; kind: 'advisory' | 'coverage'; advisoryId?: string; key: string }
export interface CheckResult { findings: Finding[]; matched: number; unknown: number; checkedAt: string; warnings: string[]; inventoryCounts: ReturnType<typeof inventoryCounts>; advisoryCounts: ReturnType<typeof advisoryCounts> }
export async function checkFiles(files: MetadataFile[], fetcher: typeof fetch = fetch): Promise<CheckResult> {
  const graph = parseDependencies(files.map(file => ({ path: file.path, data: JSON.parse(file.content) })));
  const report = await checkVulnerabilities(graph, fetcher);
  const findings: Finding[] = [];
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  let matched = 0, unknown = 0;
  for (const check of report.checks) {
    const node = byId.get(check.nodeId)!;
    if (node.isProject) continue;
    const file = files.find(f => f.path === node.project) ?? files[0];
    if (!file) continue;
    const token = JSON.stringify(node.installPath || node.name);
    const nameToken = JSON.stringify(node.name);
    let offset = file.content.indexOf(token); let length = token.length;
    if (offset < 0) { offset = file.content.indexOf(nameToken); length = nameToken.length; }
    if (offset < 0) { offset = 0; length = 1; }
    if (check.status === 'matched') matched++;
    for (const advisoryId of check.advisoryIds) findings.push({ path: file.path, offset, length, kind: 'advisory', advisoryId, key: JSON.stringify([node.project, node.installPath, node.name, node.version, advisoryId]), message: `${node.name}@${node.version}: OSV advisory ${advisoryId}. Location: ${node.installPath}. A version match does not prove exploitability. Review the advisory before choosing a fix.` });
    if (!check.complete || check.status === 'unknown') {
      unknown++;
      findings.push({ path: file.path, offset, length, kind: 'coverage', key: `unknown:${node.id}`, message: `${node.name}@${node.version ?? 'unresolved'}: advisory coverage is unknown or incomplete. Failed, skipped, unresolved and paginated checks are not clean results.` });
    }
  }
  const warnings = [...graph.warnings, ...report.warnings];
  if (!graph.nodes.some(n => !n.isProject)) warnings.push('No resolved library versions found. Without an inventory this check cannot establish advisory coverage.');
  for (const warning of warnings.slice(0, 100)) if (files[0]) findings.push({ path: files[0].path, offset: 0, length: 1, kind: 'coverage', key: `warning:${warning}`, message: warning });
  return { findings, matched, unknown, checkedAt: report.checkedAt, warnings, inventoryCounts: inventoryCounts(graph), advisoryCounts: advisoryCounts(graph, report) };
}
