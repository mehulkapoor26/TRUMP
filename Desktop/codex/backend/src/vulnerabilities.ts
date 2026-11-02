import semver from 'semver';
import type { DependencyGraph, VulnerabilityReport, Ecosystem } from '@traceguard/shared';
import { isOptionalPeerNotice } from './inventory.js';

/** Advisory presence is a version match, not evidence of reachable/exploitable code. */
export async function checkVulnerabilities(graph: DependencyGraph, fetcher: typeof fetch = fetch): Promise<VulnerabilityReport> {
  // Keep the existing npm-only VS Code watcher independent of Python parser runtime requirements.
  const pythonVersions = graph.nodes.some(node => node.ecosystem && node.ecosystem !== 'npm') ? await import('./ecosystems.js') : undefined;
  const report: VulnerabilityReport = {
    source: 'OSV', checkedAt: new Date().toISOString(), status: 'unavailable',
    checks: graph.nodes.map(node => ({ nodeId: node.id, status: 'unknown', complete: false, advisoryIds: [] })), warnings: [],
  };
  const checks = new Map(report.checks.map(check => [check.nodeId, check]));
  const packages = new Map<string, { name: string; version: string; ecosystem: Ecosystem; nodeIds: string[] }>();
  for (const node of graph.nodes) {
    const ecosystem = node.ecosystem ?? 'npm';
    if (node.isProject || node.advisoryEligible === false || !node.version || !(ecosystem !== 'npm' ? pythonVersions!.exactVersion(ecosystem, node.version) : semver.valid(node.version))) continue;
    const key = JSON.stringify([ecosystem, node.name, node.version]);
    const entry = packages.get(key) ?? { name: node.name, version: node.version, ecosystem, nodeIds: [] };
    entry.nodeIds.push(node.id); packages.set(key, entry);
  }
  const candidates = [...packages.values()];
  const eligible = candidates.slice(0, 1000);
  if (candidates.length > eligible.length) report.warnings.push('Only the first 1,000 unique package/version pairs were checked. Remaining packages are unknown.');
  const signal = AbortSignal.timeout(20_000);
  report.evidence = { requests: [] }; let requestCount = 0, responseBytes = 0;
  async function query(queries: unknown[]): Promise<any[]> {
    if (++requestCount > 50) throw new Error('OSV request budget exceeded');
    const record: NonNullable<VulnerabilityReport['evidence']>['requests'][number] = { queries, checkedAt: new Date().toISOString() }; report.evidence!.requests.push(record);
    try {
      const response = await fetcher('https://api.osv.dev/v1/querybatch', { method: 'POST', redirect: 'error', signal, headers: { 'Content-Type': 'application/json', 'User-Agent': 'TRACEGUARD' }, body: JSON.stringify({ queries }) });
      if (!response.ok || !response.body) { await response.body?.cancel(); throw new Error(response.status === 429 ? `OSV rate limited; retry later (Retry-After: ${response.headers.get('retry-after') ?? 'unspecified'}).` : `OSV HTTP ${response.status}`); }
      const reader = response.body.getReader(), chunks: Buffer[] = []; let bytes = 0;
      try { for (;;) { const { done, value } = await reader.read(); if (done) break; bytes += value.length; responseBytes += value.length; if (bytes > 2 * 1024 * 1024 || responseBytes > 10 * 1024 * 1024) throw new Error('OSV response budget exceeded'); chunks.push(Buffer.from(value)); } } finally { await reader.cancel(); }
      const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!Array.isArray(data.results) || data.results.length !== queries.length) throw new Error('Invalid OSV response ordering/length');
      record.results = data.results; return data.results;
    } catch (error) { record.error = error instanceof Error ? error.message : String(error); throw error; }
  }
  for (let offset = 0; offset < eligible.length; offset += 100) {
    const batch = eligible.slice(offset, offset + 100);
    try {
      const queries = batch.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version }));
      const results = await query(queries);
      for (const [index, initial] of results.entries()) {
        let result = initial; const seenTokens = new Set<string>(); const collected = new Set<string>(); let completePages = true;
        for (let page = 0; ; page++) {
          if (!result || typeof result !== 'object' || Array.isArray(result) || 'error' in result || result.vulns !== undefined && !Array.isArray(result.vulns) || (result.vulns ?? []).some((v: any) => !v || typeof v.id !== 'string' || !/^[A-Za-z0-9_.-]{1,200}$/.test(v.id))) { completePages = false; break; }
          for (const item of result.vulns ?? []) collected.add(item.id);
          const token = result.next_page_token; if (!token) break;
          if (typeof token !== 'string' || token.length > 4096 || seenTokens.has(token) || page >= 9) { completePages = false; break; }
          seenTokens.add(token);
          try { result = (await query([{ ...queries[index], page_token: token }]))[0]; } catch { completePages = false; break; }
        }
        result = { vulns: [...collected].sort().map(id => ({ id })), ...(completePages ? {} : { next_page_token: 'incomplete' }) };
        if (!result || typeof result !== 'object' || Array.isArray(result)) continue;
        if ('error' in result) continue;
        const item = result as { vulns?: unknown; next_page_token?: unknown };
        if (item.vulns !== undefined && !Array.isArray(item.vulns)) continue;
        const vulns = (item.vulns ?? []) as unknown[];
        if (vulns.some(v => !v || typeof v !== 'object' || !('id' in v) || typeof v.id !== 'string' || !/^[A-Za-z0-9_.-]{1,200}$/.test(v.id))) continue;
        const advisoryIds = [...new Set(vulns.map(v => (v as { id: string }).id))];
        const complete = !item.next_page_token;
        for (const nodeId of batch[index].nodeIds) Object.assign(checks.get(nodeId)!, { status: advisoryIds.length ? 'matched' : complete ? 'no-known' : 'unknown', complete, advisoryIds });
        if (!complete && !report.warnings.includes('OSV returned paginated results; some advisory lists are incomplete.')) report.warnings.push('OSV returned paginated results; some advisory lists are incomplete.');
      }
    } catch (error) {
      report.warnings.push(`OSV lookup failed or timed out. Unchecked packages remain unknown; retry later. ${error instanceof Error ? error.message : ''}`);
      break;
    }
  }
  const libraryChecks = graph.nodes.filter(n => !n.isProject).map(n => checks.get(n.id)!);
  report.status = libraryChecks.length && libraryChecks.every(check => check.complete) ? 'complete' : libraryChecks.some(check => check.complete || check.status === 'matched') ? 'partial' : 'unavailable';
  if (graph.warnings.some(warning => !isOptionalPeerNotice(warning)) || graph.unresolved.some(declaration => !declaration.optionalPeer)) {
    report.warnings.push('Dependency inventory is incomplete or has warnings; advisory coverage only applies to recorded resolved instances.');
    if (report.status === 'complete') report.status = 'partial';
  }
  if (!libraryChecks.length) report.warnings.push('No resolved library inventory is available; advisory coverage cannot be established.');
  if (libraryChecks.some(c => c.status === 'unknown')) report.warnings.push('Unknown means not checked or insufficient data, not safe.');
  return report;
}
