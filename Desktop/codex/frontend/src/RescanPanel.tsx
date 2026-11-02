import { useEffect, useState } from 'react';
import type { ScanComparison, ScanResult, ScanSummary } from '@traceguard/shared';
import { ScanForm } from './ScanForm';
import { Panel } from './ui';

export function RescanPanel({ scan }: { scan: ScanResult }) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [afterId, setAfterId] = useState('');
  const [sameProject, setSameProject] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [comparison, setComparison] = useState<ScanComparison>();
  const [filter, setFilter] = useState('all');
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/scans', { signal: controller.signal }).then(async r => { if (!r.ok) throw new Error('Could not load saved scans.'); setScans((await r.json()).scans); }).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    fetch(`/api/scans/${scan.id}/comparison`, { signal: controller.signal }).then(async r => { if (r.status === 404) return; if (!r.ok) throw new Error('Could not load saved comparison.'); setComparison(await r.json()); }).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    return () => controller.abort();
  }, [scan.id]);
  async function compare() {
    setBusy(true); setError('');
    try {
      const response = await fetch(`/api/scans/${afterId}/comparison`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ beforeScanId: scan.id, sameProject }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? 'Comparison failed.');
      setComparison(data);
    } catch (e) { setError(e instanceof Error ? e.message : 'Comparison failed.'); }
    finally { setBusy(false); }
  }
  return <Panel title="Before-and-after rescan" subtitle="Compare saved inventories against current OSV advisories">
    <div style={{ padding: 22 }}>
      <p className="page-description">Baseline: {scan.id} · {new Date(scan.createdAt).toLocaleString()}. Apply any fixes yourself, then scan your updated repository or ZIP. No source or dependency files are changed automatically.</p>
      <button className="button" style={{ marginTop: 14 }} disabled={busy} onClick={() => setUploading(!uploading)}>{uploading ? 'Close rescan form' : 'Scan updated repository / ZIP'}</button>
      {uploading && <ScanForm onComplete={result => { setScans(previous => [{ id: result.id, source: result.source, createdAt: result.createdAt, status: result.status, packages: result.graph?.nodes.length ?? 0, relationships: result.graph?.edges.length ?? 0, warnings: result.graph?.warnings.length ?? 0, sourceFiles: result.sourceFiles?.length ?? 0 }, ...previous]); setAfterId(result.id); setUploading(false); }} />}
      <label className="page-description" style={{ display: 'block', marginTop: 16 }}>After scan<select aria-label="After scan" value={afterId} disabled={busy} onChange={e => { setAfterId(e.target.value); setSameProject(false); }}><option value="">Choose an updated scan</option>{scans.filter(s => s.id !== scan.id).map(s => <option key={s.id} value={s.id}>{s.source} · {new Date(s.createdAt).toLocaleString()} · {s.id.slice(0, 8)}</option>)}</select></label>
      <label className="page-description" style={{ display: 'block', marginTop: 12 }}><input type="checkbox" checked={sameProject} disabled={busy} onChange={e => setSameProject(e.target.checked)} /> These scans represent the same project, with the selected scan as the after state.</label>
      <button className="button" style={{ marginTop: 12 }} disabled={busy || !afterId || !sameProject} onClick={() => void compare()}>{busy ? 'Checking both inventories…' : 'Compare vulnerabilities'}</button>
      {error && <p className="error-banner" role="alert">{error}</p>}
      {comparison && <><p className="page-description" role="status">Comparison {comparison.id} · {new Date(comparison.generatedAt).toLocaleString()}<br />Before: {comparison.before.scanId}<br />After: {comparison.after.scanId}</p>
        <p className="page-description">Resolved: {comparison.counts.resolved} · Remaining: {comparison.counts.remaining} · Newly introduced: {comparison.counts.newlyIntroduced} · Unverifiable: {comparison.counts.unverifiable}</p>
        <a className="text-link" href={`/api/scans/${comparison.after.scanId}/comparison`} download>Download comparison JSON</a>
        <p className="page-description">To include this comparison in PDF and JSON security reports, <a className="text-link" href={`#/scans/${comparison.after.scanId}/overview`}>open the after scan</a> and regenerate reports. Existing report snapshots are preserved until regeneration.</p>
        <select aria-label="Filter comparison issues" value={filter} onChange={e => setFilter(e.target.value)}><option value="all">All outcomes</option>{['resolved', 'remaining', 'newlyIntroduced', 'unverifiable'].map(status => <option key={status}>{status}</option>)}</select>
        {comparison.issues.filter(i => filter === 'all' || i.status === filter).slice(0, 200).map((issue, i) => <details key={i} style={{ marginTop: 14 }}><summary>{issue.packageName} {issue.advisoryId ?? '(coverage)'} — {issue.status}</summary><p className="page-description">{issue.reason}</p>{(['before', 'after'] as const).map(side => <div key={side}><strong>{side}</strong>{issue[side].length ? issue[side].map(n => <p className="page-description" key={n.nodeId}>{n.version ?? 'unresolved'} · {n.project}: {n.installPath}{n.advisoryMatched === undefined ? '' : n.advisoryMatched ? ' · advisory observed' : ' · advisory not observed (see coverage)'}</p>) : <p className="page-description">No observed matching instance</p>}</div>)}</details>)}
        {comparison.issues.length > 200 && <p className="page-description">Showing up to 200 outcomes. Filter or download JSON for all outcomes.</p>}
        {!comparison.issues.length && <p className="page-description">No advisory differences or coverage issues observed. This is not a safety guarantee.</p>}
        {(['before', 'after'] as const).map(side => <details key={side} style={{ marginTop: 14 }}><summary>{side} coverage evidence</summary><p className="page-description">OSV checked: {comparison[side].advisoryCheckedAt} · {comparison[side].unresolvedDependencies} unresolved declarations</p><ul>{[...comparison[side].inventoryWarnings, ...comparison[`${side}Checks`].warnings].map((warning, i) => <li className="page-description" key={i}>{warning}</li>)}</ul></details>)}
        <details style={{ marginTop: 18 }}><summary>Comparison scope and limitations</summary><ul>{comparison.limitations.map((limit, i) => <li key={i} className="page-description">{limit}</li>)}</ul></details>
      </>}
    </div>
  </Panel>;
}
