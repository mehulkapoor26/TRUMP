import { ReachabilityPanel } from './ReachabilityPanel';
import { useEffect, useMemo, useState } from 'react';
import { Background, Controls, MarkerType, MiniMap, Position, ReactFlow, type Node, type Edge, type ReactFlowInstance } from '@xyflow/react';
import type { DependencyGraph as Graph, VulnerabilityReport, SourceFileInfo, ReachabilityReport } from '@traceguard/shared';
import { dependencyImpact, graphIndex, graphLayout } from './graph-model';

type Props = { graph: Graph; scanId: string; sourceFiles?: SourceFileInfo[]; initialSelected?: string; advisoryReport?: VulnerabilityReport; onAdvisoryReport?: (report: VulnerabilityReport | undefined) => void; onReachabilityReport?: (report: ReachabilityReport) => void };
export function DependencyGraph({ graph, scanId, sourceFiles = [], initialSelected, advisoryReport, onAdvisoryReport, onReachabilityReport }: Props) {
  const [selected, setSelected] = useState<string | undefined>(initialSelected);
  useEffect(() => { if (initialSelected) setSelected(initialSelected); }, [initialSelected]);
  const [flow, setFlow] = useState<ReactFlowInstance<Node, Edge>>();
  useEffect(() => {
    if (!selected || !flow) return;
    const frame = requestAnimationFrame(() => void flow.fitView({ nodes: [{ id: selected }], padding: 1, minZoom: 0.25, maxZoom: 1, duration: 250 }));
    return () => cancelAnimationFrame(frame);
  }, [selected, flow]);
  const [search, setSearch] = useState('');
  const [report, setReport] = useState<VulnerabilityReport | undefined>(advisoryReport);
  useEffect(() => setReport(advisoryReport), [advisoryReport]);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState('');
  const index = useMemo(() => graphIndex(graph), [graph]);
  const impact = useMemo(() => selected ? dependencyImpact(graph, selected) : undefined, [graph, selected]);
  const layout = useMemo(() => graphLayout(graph, selected), [graph, selected]);
  const checks = useMemo(() => new Map(report?.checks.map(check => [check.nodeId, check]) ?? []), [report]);
  const node = selected ? index.nodes.get(selected) : undefined;
  const selectedCheck = selected ? checks.get(selected) : undefined;
  const label = (id: string) => { const n = index.nodes.get(id)!; return `${n.name}@${n.version ?? 'unresolved'}`; };
  const kind = (id: string) => { const n = index.nodes.get(id)!; return n.isProject ? 'Project' : [n.direct && 'Direct', n.transitive && 'Transitive'].filter(Boolean).join(' + ') || (n.ecosystem === 'PyPI' ? 'Unknown relationship' : 'Locked instance'); };
  const status = (id: string) => checks.get(id)?.status === 'matched' ? 'Advisory match' : checks.get(id)?.status === 'no-known' ? 'No known match' : 'Unknown / not checked';
  const nodes: Node[] = useMemo(() => layout.nodes.map(({ node, position }) => {
    const matched = checks.get(node.id)?.status === 'matched';
    const upstream = impact?.ancestors.has(node.id);
    return { id: node.id, position, sourcePosition: Position.Right, targetPosition: Position.Left, selected: node.id === selected,
      data: { label: <div className="text-left"><strong className="block break-all">{node.name}</strong><span className="block text-xs">{node.version ?? 'Unresolved version'} · {kind(node.id)}</span><span className="mt-2 block text-xs">{status(node.id)}</span></div> },
      style: { width: 240, background: matched ? '#451a24' : node.isProject ? '#12372d' : '#172033', color: '#f1f5f9', border: `2px solid ${node.id === selected ? '#c4b5fd' : matched ? '#fb7185' : upstream ? '#fbbf24' : node.direct ? '#34d399' : '#64748b'}`, borderRadius: 10 },
      ariaLabel: `${label(node.id)}, ${kind(node.id)}, ${status(node.id)}`,
    };
  }), [layout, checks, selected, impact, index]);
  const edges: Edge[] = useMemo(() => layout.edges.map((edge, i) => {
    const onImpactPath = !!selected && (edge.to === selected || !!impact?.ancestors.has(edge.to)) && !!impact?.ancestors.has(edge.from);
    return { id: `${edge.from}:${edge.to}:${edge.kind}:${i}`, source: edge.from, target: edge.to, label: edge.kind,
      markerEnd: { type: MarkerType.ArrowClosed, color: onImpactPath ? '#fbbf24' : '#64748b' },
      style: { stroke: onImpactPath ? '#fbbf24' : '#64748b', strokeWidth: onImpactPath ? 2.5 : 1 },
      labelStyle: { fill: '#e2e8f0', fontSize: 10 }, labelBgStyle: { fill: '#0f172a' },
    };
  }), [layout, impact, selected]);
  async function checkAdvisories() {
    setChecking(true); setError(''); setReport(undefined); onAdvisoryReport?.(undefined);
    try {
      const response = await fetch(`/api/scans/${scanId}/vulnerabilities`, { method: 'POST' });
      const data = await response.json(); if (!response.ok) throw new Error(data.error ?? 'Advisory check failed.');
      setReport(data); onAdvisoryReport?.(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Advisory check failed.'); }
    finally { setChecking(false); }
  }
  const matches = search.trim() ? graph.nodes.filter(n => `${n.name} ${n.version ?? ''} ${n.installPath}`.toLowerCase().includes(search.toLowerCase().trim())) : [];
  return <section aria-labelledby="dependency-graph-heading" className="mt-8 border-t border-slate-700 pt-6">
    <h3 id="dependency-graph-heading" className="text-xl font-semibold">Dependency graph</h3>
    <p className="mt-2 text-sm text-slate-400">Arrows point from parent to dependency. Green borders mark direct dependencies, slate borders mark other locked instances, red marks advisory matches, and amber marks ancestors of the selected package.</p>
    <div className="my-4 space-y-3">
      <button disabled={checking} onClick={() => void checkAdvisories()} className="rounded-lg bg-rose-200 px-4 py-2 font-semibold text-slate-950 disabled:opacity-50">{checking ? 'Checking security database…' : 'Check security findings'}</button>
      <p className="text-xs text-slate-400">Sends package names and resolved versions to OSV. Source files are not sent. Unknown status does not mean safe.</p>
      {error && <p role="alert" className="text-rose-300">{error}</p>}
      {report && <p role="status" className="text-sm">OSV lookup: {report.status} · {report.checks.filter(c => c.status === 'matched').length} package instances with advisory matches · checked {new Date(report.checkedAt).toLocaleString()}</p>}
      {report?.warnings.map(w => <p key={w} className="text-sm text-amber-300">{w}</p>)}
      <label className="block text-sm">Find a package instance<input value={search} onChange={e => setSearch(e.target.value)} placeholder="Name, version, or installation path" className="mt-2 block w-full rounded border border-slate-700 bg-slate-950 p-3" /></label>
      {search.trim() && <div className="max-h-48 space-y-2 overflow-auto" aria-label="Package search results">{matches.slice(0, 30).map(n => <button key={n.id} className="block w-full rounded border border-slate-700 p-2 text-left text-sm" onClick={() => setSelected(n.id)}>{label(n.id)} · {n.project}: {n.installPath || '<root>'}</button>)}<p className="text-xs text-slate-400">{matches.length} matches; showing up to 30. Refine the search to find a specific installation.</p></div>}
    </div>
    <div className="h-[520px] overflow-hidden rounded-xl border border-slate-700" aria-label="Interactive dependency graph">
      <ReactFlow onInit={setFlow} nodes={nodes} edges={edges} onNodeClick={(_event, node) => setSelected(node.id)} nodesDraggable={false} nodesConnectable={false} edgesReconnectable={false} fitView minZoom={0.05} maxZoom={2} colorMode="dark" onlyRenderVisibleElements>
        <Background /><Controls showInteractive={false} /><MiniMap pannable zoomable nodeColor={n => checks.get(n.id)?.status === 'matched' ? '#fb7185' : '#64748b'} />
      </ReactFlow>
    </div>
    <p className="mt-2 text-xs text-slate-400">Showing {layout.nodes.length} of {graph.nodes.length} nodes and {layout.edges.length} of {graph.edges.length} edges.{layout.omitted > 0 && ' The canvas is limited to 300 nodes. Search and select any package to bring it and its dependency context into view.'}</p>
    <div className="mt-5 grid gap-4 lg:grid-cols-2">
      <div className="rounded-xl border border-amber-800 bg-amber-950/20 p-4"><h4 className="font-semibold text-amber-200">Dependency impact</h4><p className="mt-2 text-sm">{impact ? `${impact.ancestors.size} ancestor package/project instances depend on the selected package through the locked graph.` : 'Select a package to trace parents and paths from project roots.'} A dependency path shows potential propagation through package relationships. It does not prove that vulnerable functions execute.</p></div>
      <div className="rounded-xl border border-slate-700 bg-slate-950 p-4"><h4 className="font-semibold">Actual exploitability: not assessed</h4><p className="mt-2 text-sm text-slate-300">Advisory matches concern the recorded package version. Scoped call analysis can investigate exported-function paths separately. Runtime configuration, attacker input, deployment exposure, and mitigations remain unassessed. Direct/transitive depth and advisory presence do not establish an exploitable application.</p></div>
    </div>
    {node && <aside aria-label="Selected package details" className="mt-5 space-y-4 rounded-xl border border-violet-400 p-5">
      <h4 className="break-all text-lg font-semibold">{label(node.id)}</h4>
      <p>{node.ecosystem ?? 'npm'} · {kind(node.id)} · {status(node.id)}</p><p className="break-all font-mono text-xs">{node.project}: {node.installPath || '<root>'}</p>
      <p className="text-sm">{selectedCheck?.status === 'no-known' ? 'No known OSV advisory match was returned at the check time. This is not a safety guarantee.' : selectedCheck?.status === 'matched' ? 'This recorded version has OSV advisory matches. Application exploitability is not assessed.' : node.isProject ? 'Local project metadata is not queried as a published npm package.' : 'Advisory status is unknown. Run a check; unavailable results remain unknown.'}</p>
      {selectedCheck?.status === 'matched' && <ul className="space-y-1">{selectedCheck.advisoryIds.map(id => <li key={id}><a className="text-rose-300 underline" target="_blank" rel="noreferrer" href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`}>{id}</a></li>)}{!selectedCheck.complete && <li className="text-amber-300">Advisory list is incomplete.</li>}</ul>}
      <h5 className="font-semibold">Paths from project roots</h5>
      {impact?.paths.length ? <ul className="space-y-2 text-sm">{impact.paths.map((path, i) => <li key={i} className="break-words">{path.ids.map(label).join(' → ')}{path.truncated && ' → … (path limited to 100 nodes)'}</li>)}</ul> : <p className="text-sm">No path from a known project root. This is a locked instance whose root relationship is unresolved.</p>}
      <p className="text-xs text-slate-400">One shortest path per root; at most five roots. Multiple dependency routes can exist.{impact?.pathsLimited && ' Additional root paths are omitted.'}</p>
      {(['parents', 'children'] as const).map(direction => {
        const relationships = graph.edges.filter(edge => direction === 'parents' ? edge.to === node.id : edge.from === node.id);
        return <div key={direction}><h5 className="font-semibold">{direction === 'parents' ? 'Immediate parents' : 'Immediate children'} ({relationships.length})</h5><ul className="mt-2 max-h-60 space-y-2 overflow-auto text-sm">{relationships.map((edge, i) => { const other = direction === 'parents' ? edge.from : edge.to; return <li key={i}><button className="text-left text-emerald-300 underline" onClick={() => setSelected(other)}>{label(other)}</button> · {edge.kind}, requested {edge.requested}<p className="break-all text-xs text-slate-400">{index.nodes.get(other)?.installPath || '<root>'}</p></li>; })}</ul></div>;
      })}
      {graph.unresolved.filter(item => item.from === node.id).map((item, i) => <p key={i} className="text-sm text-amber-300">Unresolved child: {item.name}@{item.requested} ({item.kind})</p>)}
      {!node.isProject && <ReachabilityPanel key={node.id} scanId={scanId} node={node} sourceFiles={sourceFiles} advisoryIds={selectedCheck?.advisoryIds ?? []} onReport={onReachabilityReport} />}
    </aside>}
  </section>;
}
