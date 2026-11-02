import { useState, type FormEvent } from 'react';
import type { DependencyNode, ReachabilityReport, SourceFileInfo } from '@traceguard/shared';

type Props = { scanId: string; node: DependencyNode; sourceFiles: SourceFileInfo[]; advisoryIds: string[]; onReport?: (report: ReachabilityReport) => void; initialReport?: ReachabilityReport };
export function ReachabilityPanel({ scanId, node, sourceFiles, advisoryIds, onReport, initialReport }: Props) {
  const [file, setFile] = useState(initialReport?.coverage.entrypoints[0]?.file ?? sourceFiles[0]?.path ?? '');
  const [symbol, setSymbol] = useState(initialReport?.coverage.entrypoints[0]?.symbol ?? '<module>');
  const [exportName, setExportName] = useState(initialReport?.target.exportName ?? '');
  const [subpath, setSubpath] = useState(initialReport?.target.subpath ?? '');
  const [advisoryId, setAdvisoryId] = useState('');
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ReachabilityReport | undefined>(initialReport);
  const [error, setError] = useState('');
  if (node.ecosystem === 'Maven') return <section aria-label="Scoped function reachability"><h5>Java reachability</h5><p role="status">UNKNOWN — Java static reachability is not implemented. Maven, Gradle and uploaded Java code are never executed; JavaScript AST analysis does not apply.</p></section>;
  if (node.ecosystem === 'PyPI') return <section aria-label="Scoped function reachability" className="mt-6 border-t border-slate-700 pt-5"><h5>Python reachability</h5><p role="status">UNKNOWN — Python source reachability is not implemented. The JavaScript AST analyzer does not analyze Python. Dependency and vulnerability evidence remains available; no submitted Python code is executed.</p></section>;
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setReport(undefined);
    try {
      const response = await fetch(`/api/scans/${scanId}/reachability`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entrypoints: [{ file, symbol }], target: { packageNodeId: node.id, exportName: exportName.trim(), subpath: subpath.trim(), ...(advisoryId ? { advisoryId } : {}) } }) });
      const result = await response.json(); if (!response.ok) throw new Error(result.error ?? 'Analysis request failed.');
      setReport(result);
      onReport?.(result);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Analysis request failed.'); }
    finally { setBusy(false); }
  }
  return <section aria-label="Scoped function reachability" className="mt-6 border-t border-slate-700 pt-5">
    <h5 className="font-semibold">Scoped function reachability</h5>
    <p className="mt-2 text-sm text-slate-300">Choose an application entrypoint and the affected exported function. Function mapping is user-declared; an advisory ID alone does not identify a vulnerable function. This investigates static calls, not exploitability.</p>
    {!sourceFiles.length ? <p className="mt-3 text-amber-300">Source snapshot unavailable. Rescan with source files to analyze reachability. Current reachability: UNKNOWN.</p> : <form onSubmit={submit} className="mt-4 grid gap-3 sm:grid-cols-2">
      <label className="text-sm">Entry source file<select disabled={busy} value={file} onChange={e => { setFile(e.target.value); setReport(undefined); }} className="mt-1 block w-full rounded border border-slate-600 bg-slate-950 p-2">{sourceFiles.map(f => <option key={f.path} value={f.path}>{f.path}</option>)}</select></label>
      <label className="text-sm">Entry export or &lt;module&gt;<input required disabled={busy} value={symbol} onChange={e => { setSymbol(e.target.value); setReport(undefined); }} className="mt-1 block w-full rounded border border-slate-600 p-2" /></label>
      <label className="text-sm">Affected export (user-declared)<input disabled={busy} value={exportName} onChange={e => { setExportName(e.target.value); setReport(undefined); }} placeholder="e.g. template, parse, or default" className="mt-1 block w-full rounded border border-slate-600 p-2" /></label>
      <label className="text-sm">Package subpath (optional)<input disabled={busy} value={subpath} onChange={e => { setSubpath(e.target.value); setReport(undefined); }} placeholder="e.g. parser" className="mt-1 block w-full rounded border border-slate-600 p-2" /></label>
      <label className="text-sm">Advisory context (optional)<select disabled={busy} value={advisoryId} onChange={e => { setAdvisoryId(e.target.value); setReport(undefined); }} className="mt-1 block w-full rounded border border-slate-600 bg-slate-950 p-2"><option value="">No advisory selected</option>{advisoryIds.map(id => <option key={id}>{id}</option>)}</select></label>
      <div className="flex items-end"><button disabled={busy} className="rounded bg-violet-200 px-4 py-2 font-semibold text-slate-950 disabled:opacity-50">{busy ? 'Analyzing static calls…' : 'Analyze scoped reachability'}</button></div>
    </form>}
    {error && <p role="alert" className="mt-3 text-rose-300">{error}</p>}
    {report && <div className="mt-4 space-y-4">
      <p role="status" className="font-semibold text-violet-200">{report.status}{report.status === 'NOT REACHABLE' ? ' — within declared analysis coverage only' : report.status === 'REACHABLE' ? ' — static exported-boundary call path' : ' — insufficient static evidence'}</p>
      <p className="text-sm">{report.reason}</p><p className="text-xs text-amber-200">Mapping: {report.mapping}. Actual exploitability remains not assessed.</p>
      <details open><summary className="cursor-pointer font-semibold">Declared analysis coverage</summary><ul className="mt-2 space-y-1 text-sm">
        <li>Entrypoints: {report.coverage.entrypoints.map(e => `${e.file}#${e.symbol}`).join(', ')}</li>
        <li>Boundary: {report.coverage.boundary}</li><li>{report.coverage.functionsVisited} functions visited · {report.coverage.callsExamined} calls examined · {report.coverage.sourceFilesAvailable} source files captured</li>
        <li>Complete for declared entrypoints: {report.coverage.completeForDeclaredEntrypoints ? 'yes, under the stated model' : 'no'}</li>
        <li>Traversed files: {report.coverage.analyzedFiles.join(', ') || 'none'}</li><li>Source files skipped by capture limits: {report.coverage.skippedSources.length}</li>
      </ul></details>
      <div><h6 className="font-semibold">Source file and line evidence</h6><ol className="mt-2 space-y-3">{report.evidence.map((e, i) => <li key={i} className="rounded bg-slate-950 p-3 text-xs"><p className="font-mono">{e.file}:{e.line}:{e.column} · {e.kind}</p><p className="mt-1 break-all">{e.from} → {e.to}</p><pre className="mt-2 whitespace-pre-wrap break-all">{e.snippet}</pre></li>)}</ol></div>
      {report.gaps.length > 0 && <div><h6 className="font-semibold text-amber-200">Analysis gaps</h6><ul className="mt-2 space-y-2 text-sm">{report.gaps.map((g, i) => <li key={i}>{g.evidence && <span className="font-mono">{g.evidence.file}:{g.evidence.line} · </span>}{g.reason}</li>)}</ul></div>}
      <details><summary className="cursor-pointer font-semibold">Limitations and exclusions</summary><ul className="mt-2 space-y-2 text-sm">{report.limitations.map(item => <li key={item}>{item}</li>)}</ul></details>
    </div>}
  </section>;
}
