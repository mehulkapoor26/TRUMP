import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, ArrowRight, ChevronDown, CircleHelp, Download, FileSearch, Fingerprint, GitBranch, LayoutDashboard, Menu, Network, RefreshCw, ScanLine, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import type { HealthResponse, ReachabilityReport, ScanResult, ScanSummary, VulnerabilityReport } from '@traceguard/shared';
import { Landing } from './Landing';
import { DependencyGraph } from './DependencyGraph';
import { DashboardPage, FindingsPage, HistoryTable, ReachabilityPage, ScannerPage } from './WorkspacePages';
import { ActionLink, Badge, Brand, EmptyState, PageHeading, Panel, sourceName } from './ui';

const pages = ['dashboard', 'scanner', 'scans', 'overview', 'findings', 'dependencies', 'reachability'];
function readRoute() {
  const raw = window.location.hash.slice(1) || '/';
  const [pathAndQuery, anchor] = raw.split('#'); const [path, query] = pathAndQuery.split('?');
  const parts = path.split('/').filter(Boolean);
  return { home: !parts.length, page: parts[0] === 'scans' && parts[1] ? parts[2] ?? 'overview' : parts[0] ?? 'dashboard', id: parts[0] === 'scans' ? parts[1] : undefined, node: new URLSearchParams(query).get('node') ?? undefined, anchor };
}
function storedScan() { try { return localStorage.getItem('traceguard.lastScan') ?? undefined; } catch { return undefined; } }
async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, options); const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? `Request failed (${response.status}).`);
  return data;
}
export function App() {
  const [route, setRoute] = useState(readRoute);
  const [mobileOpen, setMobileOpen] = useState(false); const [help, setHelp] = useState(false);
  const [health, setHealth] = useState<HealthResponse>();
  const [history, setHistory] = useState<ScanSummary[]>([]); const [historyError, setHistoryError] = useState('');
  const [cache, setCache] = useState<Record<string, ScanResult>>({});
  const [lastId, setLastId] = useState(storedScan);
  const [loadingScan, setLoadingScan] = useState(false); const [scanError, setScanError] = useState('');
  const [reports, setReports] = useState<Record<string, VulnerabilityReport | undefined>>({});
  const [analyses, setAnalyses] = useState<Record<string, Record<string, ReachabilityReport>>>({});
  const [checking, setChecking] = useState<Record<string, boolean>>({}); const [checkErrors, setCheckErrors] = useState<Record<string, string>>({});
  const activeId = route.id ?? lastId; const scan = activeId ? cache[activeId] : undefined;
  const report = activeId ? reports[activeId] : undefined; const analysis = activeId ? analyses[activeId] ?? {} : {};
  const refreshHistory = useCallback(async () => {
    try { const result = await api<{ scans: ScanSummary[] }>('/api/scans'); setHistory(result.scans); setHistoryError(''); }
    catch (error) { setHistoryError(error instanceof Error ? error.message : 'Could not load scan history.'); }
  }, []);
  const refreshHealth = useCallback(async () => { try { setHealth(await api<HealthResponse>('/api/health')); } catch { setHealth(undefined); } }, []);
  useEffect(() => { const change = () => { setRoute(readRoute()); setMobileOpen(false); setHelp(false); window.scrollTo({ top: 0 }); }; window.addEventListener('hashchange', change); return () => window.removeEventListener('hashchange', change); }, []);
  useEffect(() => {
    if (!help) return;
    const previous = document.activeElement as HTMLElement | null;
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]');
    const focusables = () => [...(dialog?.querySelectorAll<HTMLElement>('button, a[href], input, select, [tabindex="0"]') ?? [])];
    focusables()[0]?.focus();
    const overflow = document.body.style.overflow; document.body.style.overflow = 'hidden';
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setHelp(false);
      if (event.key === 'Tab') {
        const elements = focusables(); const first = elements[0]; const last = elements.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    document.addEventListener('keydown', keydown);
    return () => { document.removeEventListener('keydown', keydown); document.body.style.overflow = overflow; previous?.focus(); };
  }, [help]);
  useEffect(() => { if (route.home && route.anchor) requestAnimationFrame(() => document.getElementById(route.anchor!)?.scrollIntoView({ behavior: 'smooth' })); }, [route.home, route.anchor]);
  useEffect(() => { void refreshHistory(); void refreshHealth(); const timer = setInterval(() => void refreshHealth(), 30_000); return () => clearInterval(timer); }, [refreshHistory, refreshHealth]);
  useEffect(() => {
    if (!activeId) return;
    setLastId(activeId); try { localStorage.setItem('traceguard.lastScan', activeId); } catch { /* The current route remains usable without storage. */ }
    const controller = new AbortController(); setLoadingScan(true); setScanError('');
    api<ScanResult>(`/api/scans/${encodeURIComponent(activeId)}`, { signal: controller.signal }).then(data => setCache(previous => ({ ...previous, [activeId]: data }))).catch(error => { if (!controller.signal.aborted) setScanError(error instanceof Error ? error.message : 'Could not load scan.'); }).finally(() => { if (!controller.signal.aborted) setLoadingScan(false); });
    fetch(`/api/scans/${encodeURIComponent(activeId)}/vulnerabilities`, { signal: controller.signal }).then(async response => {
      if (response.status === 404) { setReports(previous => ({ ...previous, [activeId]: undefined })); return; }
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? `Request failed (${response.status}).`);
      setReports(previous => ({ ...previous, [activeId]: data as VulnerabilityReport }));
      setCheckErrors(previous => ({ ...previous, [activeId]: '' }));
    }).catch(error => { if (!controller.signal.aborted) setCheckErrors(previous => ({ ...previous, [activeId]: error instanceof Error ? `Could not load saved security-check results: ${error.message}` : 'Could not load saved security-check results.' })); });
    return () => controller.abort();
  }, [activeId]);
  function completed(result: ScanResult) {
    setCache(previous => ({ ...previous, [result.id]: result })); setLastId(result.id);
    setReports(previous => ({ ...previous, [result.id]: undefined }));
    void refreshHistory(); window.location.hash = `/scans/${result.id}/overview`;
    void checkAdvisoriesFor(result.id);
  }
  function saveReport(value: VulnerabilityReport | undefined) { if (activeId) setReports(previous => ({ ...previous, [activeId]: value })); }
  function saveAnalysis(value: ReachabilityReport) { if (activeId) setAnalyses(previous => ({ ...previous, [activeId]: { ...previous[activeId], [value.target.packageNodeId]: value } })); }
  async function checkAdvisoriesFor(id: string) {
    setChecking(p => ({ ...p, [id]: true })); setCheckErrors(p => ({ ...p, [id]: '' })); setReports(p => ({ ...p, [id]: undefined }));
    try { const value = await api<VulnerabilityReport>(`/api/scans/${id}/vulnerabilities`, { method: 'POST' }); setReports(p => ({ ...p, [id]: value })); }
    catch (error) { setCheckErrors(p => ({ ...p, [id]: error instanceof Error ? error.message : 'Advisory check unavailable.' })); }
    finally { setChecking(p => ({ ...p, [id]: false })); }
  }
  function checkAdvisories() { if (activeId && !checking[activeId]) void checkAdvisoriesFor(activeId); }
  const scopedHref = (page: string) => activeId ? `#/scans/${activeId}/${page}` : `#/${page}`;
  const isOverview = route.page === 'dashboard' || route.page === 'overview';
  const nav = [
    { label: 'Project results', page: 'dashboard', icon: LayoutDashboard, href: activeId ? scopedHref('overview') : '#/dashboard', active: isOverview },
    { label: 'Scan another project', page: 'scanner', icon: ScanLine, href: '#/scanner', active: route.page === 'scanner' },
    { label: 'Saved scans', page: 'scans', icon: FileSearch, href: '#/scans', active: route.page === 'scans' },
    { label: 'Security findings', page: 'findings', icon: ShieldAlert, href: scopedHref('findings'), active: route.page === 'findings' },
    { label: 'Dependency map', page: 'dependencies', icon: Network, href: scopedHref('dependencies'), active: route.page === 'dependencies' },
    { label: 'Function paths', page: 'reachability', icon: Fingerprint, href: scopedHref('reachability'), active: route.page === 'reachability' },
  ];
  const title = nav.find(n => n.active)?.label ?? 'Workspace';
  const hasScopedError = !['scanner', 'scans'].includes(route.page) && activeId && scanError;
  const noScan = <EmptyState icon={<ScanLine size={32} />} title="Choose a scan to investigate" action={<ActionLink href="#/scanner">Scan a repository</ActionLink>}>Run a scan or choose a saved scan from the selector. This page will use its real dependency and source analysis data.</EmptyState>;
  if (route.home) return <Landing online={!!health} />;
  return <div className="workspace">
    {mobileOpen && <button aria-label="Close navigation overlay" className="sidebar-overlay" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'open' : ''}`}><div className="sidebar-brand"><Brand /><button className="icon-button mobile-close" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X size={19} /></button></div><div className="workspace-label"><span className="workspace-avatar">TG</span><span>Local workspace<small>Dependency intelligence</small></span><span className="local-label">LOCAL</span></div><p className="nav-section-label">WORKSPACE</p><nav aria-label="Workspace navigation">{nav.slice(0, 3).map(n => <a key={n.page} href={n.href} className={n.active ? 'nav-link active' : 'nav-link'} aria-current={n.active ? 'page' : undefined}><n.icon size={18} />{n.label}{n.page === 'scans' && <span className="nav-count">{history.length}</span>}</a>)}<p className="nav-section-label analysis-label">ANALYSIS</p>{nav.slice(3).map(n => <a key={n.page} href={n.href} className={n.active ? 'nav-link active' : 'nav-link'} aria-current={n.active ? 'page' : undefined}><n.icon size={18} />{n.label}{n.page === 'findings' && report && report.checks.some(c => c.status === 'matched') && <span className="nav-count risk-count">{report.checks.filter(c => c.status === 'matched').length}</span>}</a>)}</nav><div className="sidebar-bottom"><div className="safe-analysis"><ShieldCheck size={20} /><strong>Evidence first.</strong><p>Dependency impact, function reachability, and exploitability stay distinct.</p><button className="text-link" onClick={() => setHelp(true)}>Understand analysis scope<ArrowRight size={13} /></button></div><button className="service-status" onClick={() => void refreshHealth()} title="Refresh API health"><i className={health ? 'status-dot' : 'status-dot offline'} /><span>{health ? 'Analysis service online' : 'Service unavailable'}</span><RefreshCw size={12} /></button></div></aside>
    <div className="workspace-main"><header className="workspace-topbar"><button className="icon-button mobile-toggle" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={21} /></button><div className="breadcrumbs"><span>Workspace</span><ChevronDown size={12} className="breadcrumb-chevron" /><strong>{title}</strong></div><div className="topbar-actions"><a className="back-to-site" href="#/"><ArrowLeft size={14} />Website</a><button className="icon-button" aria-label="Analysis scope and help" onClick={() => setHelp(true)}><CircleHelp size={18} /></button><span className="local-user" title="Local workspace">TG</span></div></header>
      <main id="main-content" className="workspace-content">
        {!['scanner', 'scans'].includes(route.page) && <div className="scan-context"><span className="context-label"><GitBranch size={16} />ACTIVE SCAN</span><select aria-label="Active scan" value={activeId && (history.some(s => s.id === activeId) || scan) ? activeId : ''} onChange={e => { if (e.target.value) window.location.hash = `/scans/${e.target.value}/${isOverview ? 'overview' : route.page}`; }}><option value="">Select a scan…</option>{scan && !history.some(s => s.id === scan.id) && <option value={scan.id}>{sourceName(scan.source)} · {scan.id.slice(0, 8)}</option>}{history.map(s => <option key={s.id} value={s.id}>{sourceName(s.source)} · {s.id.slice(0, 8)}</option>)}</select><button className="icon-button" aria-label="Refresh scan history" onClick={() => void refreshHistory()}><RefreshCw size={15} /></button>{scan?.sbom && <a className="download-compact" href={`/api/scans/${scan.id}/sbom`} download><Download size={14} />Export SBOM</a>}</div>}
        {historyError && <div className="error-banner" role="alert">Scan history unavailable: {historyError}<button onClick={() => void refreshHistory()}>Retry</button></div>}
        {hasScopedError ? <div className="error-banner" role="alert">Could not load this scan: {scanError}<a href="#/scans">Choose another scan</a></div> : loadingScan && !scan && !['scanner', 'scans'].includes(route.page) ? <div className="loading-state" role="status"><span className="loading-ring" />Loading saved scan…</div> : <>
          {route.page === 'scanner' && <ScannerPage onComplete={completed} />}
          {route.page === 'scans' && <><PageHeading eyebrow="WORKSPACE / SCAN HISTORY" title="Your scans" description="Return to the evidence. All saved repository and archive scans in this workspace." action={<ActionLink href="#/scanner">New scan</ActionLink>} /><Panel title="Scan history" subtitle="Latest 50 saved records · advisory checks run on demand" action={<button className="button button-secondary button-small" onClick={() => void refreshHistory()}><RefreshCw size={14} />Refresh</button>}><HistoryTable scans={history} /></Panel></>}
          {isOverview && <DashboardPage scans={history} scan={scan} report={report} reports={Object.values(analysis)} checking={!!activeId && !!checking[activeId]} checkError={activeId ? checkErrors[activeId] ?? '' : ''} onCheck={() => void checkAdvisories()} />}
          {route.page === 'findings' && (scan ? <FindingsPage key={scan.id} scan={scan} report={report} checking={!!checking[scan.id]} error={checkErrors[scan.id] ?? ''} analyses={analysis} onCheck={() => void checkAdvisories()} /> : noScan)}
          {route.page === 'dependencies' && (scan?.graph ? <><PageHeading eyebrow="ANALYSIS / PACKAGE RELATIONSHIPS" title="Dependency graph" description="Follow the actual relationships. Explore direct, transitive, and duplicate package instances." action={<Badge tone="green">{scan.graph.nodes.length} nodes · {scan.graph.edges.length} edges</Badge>} /><div className="surface graph-surface"><DependencyGraph key={scan.id} graph={scan.graph} scanId={scan.id} sourceFiles={scan.sourceFiles} initialSelected={route.node} advisoryReport={report} onAdvisoryReport={saveReport} onReachabilityReport={saveAnalysis} /></div></> : noScan)}
          {route.page === 'reachability' && (scan ? <ReachabilityPage key={scan.id} scan={scan} report={report} selectedId={route.node} analysis={analysis} onReport={saveAnalysis} /> : noScan)}
          {!pages.includes(route.page) && <EmptyState icon={<FileSearch size={30} />} title="Page not found" action={<ActionLink href="#/dashboard">Return to workspace</ActionLink>}>This route does not exist. Your saved scans are still available in the workspace.</EmptyState>}
        </>}
        <footer className="workspace-footer"><span><ShieldCheck size={13} />TRACEGUARD / SOFTWARE SUPPLY CHAIN INTELLIGENCE</span><button onClick={() => setHelp(true)}>Analysis scope & limitations<ArrowRight size={12} /></button></footer>
      </main>
    </div>
    {help && <div className="modal-backdrop" onClick={() => setHelp(false)}><section role="dialog" aria-modal="true" aria-labelledby="help-title" className="help-modal" onClick={e => e.stopPropagation()}><button className="icon-button modal-close" aria-label="Close help" onClick={() => setHelp(false)}><X size={20} /></button><span className="feature-icon"><ShieldCheck size={27} /></span><p className="eyebrow">UNDERSTAND THE EVIDENCE</p><h2 id="help-title">Clarity includes knowing the limits.</h2><dl><dt>Dependency inventory</dt><dd>Resolved versions and parent-child relationships come from captured npm manifests and lockfiles. Missing data is reported.</dd><dt>Advisory findings</dt><dd>OSV checks package names and versions. A match is not proof of vulnerable code executing; no known match is not a safety guarantee.</dd><dt>Scoped function reachability</dt><dd>You declare entrypoints and an affected export. Static traversal returns REACHABLE, NOT REACHABLE within declared coverage, or UNKNOWN, with source-line evidence. The export mapping is user-supplied.</dd><dt>Actual exploitability</dt><dd>Not assessed. Runtime feasibility, attacker control, deployment exposure, and mitigations need separate investigation.</dd><dt>Local data</dt><dd>Scan records and bounded source snapshots stay in local storage on the backend. Anyone who can reach this local server can inspect scans. No source code is executed.</dd></dl><button className="button" onClick={() => setHelp(false)}>Understood<ArrowRight size={16} /></button></section></div>}
  </div>;
}
