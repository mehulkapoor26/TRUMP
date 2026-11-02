import { RescanPanel } from './RescanPanel';
import { ReportsPanel } from './ReportsPanel';
import { useEffect, useState } from 'react';
import { ArrowRight, Boxes, CheckCheck, ChevronRight, Clock3, Code2, ExternalLink, FileJson2, FileSearch, Fingerprint, GitBranch, GitBranch as Github, Network, RefreshCw, ScanLine, Search, ShieldAlert, ShieldCheck, Upload, TriangleAlert } from 'lucide-react';
import type { ReachabilityReport, ReportBundle, ScanResult, ScanSummary, VulnerabilityReport } from '@traceguard/shared';
import { ActionLink, Badge, EmptyState, formatDate, Metric, PageHeading, Panel, sourceName, TextLink } from './ui';
import { ScanForm } from './ScanForm';
import { ReachabilityPanel } from './ReachabilityPanel';
import { DependencyGraph } from './DependencyGraph';
import { AdvisoryMarkdown, advisoryImpact, advisorySentences, safeHref } from './advisory-content';

export function ScannerPage({ onComplete }: { onComplete: (scan: ScanResult) => void }) {
  return <><PageHeading eyebrow="START HERE" title="Scan your project" description="Choose a public GitHub link or project ZIP. We’ll show what we could check and what still needs attention." /><ScanForm onComplete={onComplete} /><p className="page-description">Project files currently supported: npm, Python requirements and Poetry, Maven POM files, and supported Gradle lockfiles. Other formats are clearly marked unsupported.</p></>;
}

export function HistoryTable({ scans, compact = false }: { scans: ScanSummary[]; compact?: boolean }) {
  const [query, setQuery] = useState(''); const [order, setOrder] = useState('newest');
  const filtered = scans.filter(s => `${s.source} ${s.id}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => order === 'newest' ? b.createdAt.localeCompare(a.createdAt) : a.createdAt.localeCompare(b.createdAt));
  return <>{!compact && <div className="table-toolbar"><label className="search-field"><Search size={17} /><input aria-label="Search scans" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search repository or scan ID…" /></label><select aria-label="Sort scans" value={order} onChange={e => setOrder(e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select><span>{filtered.length} scans</span></div>}
    {scans.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Repository / source</th><th>Status</th><th>Packages</th><th>Created</th><th><span className="sr-only">Open scan</span></th></tr></thead><tbody>{filtered.slice(0, compact ? 5 : 50).map(scan => <tr key={scan.id}><td><a href={`#/scans/${scan.id}/overview`} className="source-cell"><span className="source-icon">{scan.source.startsWith('https:') ? <Github size={18} /> : <Upload size={18} />}</span><span><strong>{sourceName(scan.source)}</strong><small>{scan.id.slice(0, 8)} · {scan.relationships} relationships</small></span></a></td><td><Badge tone="green">Completed</Badge></td><td className="mono">{scan.packages}</td><td className="muted nowrap">{formatDate(scan.createdAt)}</td><td><a href={`#/scans/${scan.id}/overview`} className="icon-button" aria-label={`Open scan ${scan.id}`}><ChevronRight size={18} /></a></td></tr>)}</tbody></table>{filtered.length === 0 && <p className="table-empty">No scans match your search.</p>}</div> : <EmptyState icon={<FileSearch size={28} />} title="Your first scan starts here" action={<ActionLink href="#/scanner">New scan</ActionLink>}>Scan a public repository or ZIP to populate this workspace with real analysis results.</EmptyState>}
  </>;
}

export function DashboardPage({ scans, scan, report, reports: _reports, checking, checkError, onCheck }: { scans: ScanSummary[]; scan?: ScanResult; report?: VulnerabilityReport; reports: ReachabilityReport[]; checking: boolean; checkError: string; onCheck: () => void }) {
  const graph = scan?.graph; const libraries = graph?.nodes.filter(node => !node.isProject) ?? [];
  const checks = new Map(report?.checks.map(check => [check.nodeId, check]) ?? []);
  const matched = libraries.filter(node => checks.get(node.id)?.status === 'matched');
  const unknown = libraries.filter(node => !checks.get(node.id) || !checks.get(node.id)?.complete || checks.get(node.id)?.status === 'unknown');
  const unresolved = graph?.unresolved.length ?? 0;
  const optionalPeers = graph?.unresolved.filter(item => item.optionalPeer) ?? [];
  const requiredUnresolved = graph?.unresolved.filter(item => !item.optionalPeer) ?? [];
  const unsupported = scan?.evidence?.projects.filter(project => project.status === 'unsupported') ?? [];
  const incompleteProjects = scan?.evidence?.projects.filter(project => ['partial', 'unknown', 'failed'].includes(project.status)) ?? [];
  const inventoryComplete = scan?.analysisStatus === 'analyzed' && !requiredUnresolved.length && !unsupported.length && !incompleteProjects.length;
  const checksComplete = report?.status === 'complete' && unknown.length === 0;
  const securityComplete = !!report && checksComplete && inventoryComplete;
  const lifecycle = checking ? 'Checking OSV advisories' : !report ? inventoryComplete ? 'Dependency inventory ready' : 'Partially completed' : securityComplete ? 'Security check completed' : 'Partially completed';
  const lifecycleTone = lifecycle === 'Security check completed' || lifecycle === 'Dependency inventory ready' ? 'complete' : lifecycle === 'Checking OSV advisories' ? 'working' : 'partial';
  const folderForNode = (id: string) => { const node = graph?.nodes.find(item => item.id === id); return node?.projectPath ?? node?.project ?? '.'; };
  const unresolvedFolders = [...new Set(requiredUnresolved.map(item => folderForNode(item.from)))].sort();
  const optionalPeerFolders = [...new Set(optionalPeers.map(item => folderForNode(item.from)))].sort();
  const unknownFolders = [...new Set(report ? libraries.filter(node => { const check = checks.get(node.id); return !check || !check.complete || check.status === 'unknown'; }).map(node => node.projectPath ?? node.project ?? '.') : [])].sort();
  const coverageFolders = [...new Set([...incompleteProjects.map(project => project.path || '.'), ...unsupported.map(project => project.path || '.'), ...unresolvedFolders, ...unknownFolders])].sort();
  const blockingWarnings = graph?.warnings.filter(warning => !warning.startsWith('Optional peer dependency ')) ?? [];
  const inventoryGap = !!requiredUnresolved.length || !!blockingWarnings.length || !!unsupported.length || !!incompleteProjects.length;
  const coverageGap = inventoryGap || unknown.length > 0 || !!report && report.status !== 'complete';
  const coverageCategories = [
    ...(requiredUnresolved.length ? ['Required dependency versions or relationships are missing'] : []),
    ...(blockingWarnings.length || incompleteProjects.length ? ['Lockfile or project metadata is incomplete'] : []),
    ...(unsupported.length ? ['Some dependency formats are unsupported'] : []),
    ...(report && (report.status !== 'complete' || unknown.length) ? ['Some OSV checks are incomplete or unavailable'] : []),
  ];
  const uniquePackageCount = scan?.counts?.uniquePackages ?? new Set(libraries.map(node => JSON.stringify([node.ecosystem ?? 'npm', node.name]))).size;
  const resolvedCount = libraries.filter(node => !!node.version && node.resolutionConfidence !== 'unresolved' && node.advisoryEligible !== false).length;
  const checkedCount = report ? libraries.filter(node => { const check = checks.get(node.id); return check?.status === 'matched' || check?.complete && check.status === 'no-known'; }).length : undefined;
  const noKnownFindings = !!report && matched.length === 0 && securityComplete;
  const title = !scan ? 'Your project scan' : matched.length ? 'Known security findings need review' : checking ? 'Checking OSV advisories' : noKnownFindings ? 'No known advisory matches' : lifecycle === 'Partially completed' ? 'Some dependencies could not be fully analyzed.' : 'Dependency inventory ready';

  return <><PageHeading eyebrow="PROJECT RESULTS" title="Project scan results" description={scan ? `${sourceName(scan.source)} · scanned ${formatDate(scan.createdAt)} · scan ID ${scan.id.slice(0, 8)}` : 'Add a public GitHub link or upload a ZIP to see what TRACEGUARD can check.'} action={<ActionLink href="#/scanner">Scan another project</ActionLink>} />
    {!scan ? <EmptyState icon={<FileSearch size={28} />} title="Ready when you are" action={<ActionLink href="#/scanner">Scan My Project</ActionLink>}>Choose a public GitHub repository or upload a project ZIP. The scan uses real repository files and current advisory checks.</EmptyState> : <>
      <section className={`result-summary ${matched.length ? 'result-summary-risk' : securityComplete ? 'result-summary-complete' : 'result-summary-incomplete'}`} aria-label="Project scan summary">
        <div className="result-summary-heading"><div><p className="eyebrow">PROJECT RESULTS</p><h2>{title}</h2><p>{matched.length ? `${matched.length} package instance${matched.length === 1 ? '' : 's'} match OSV advisories. A version match does not prove that affected code runs in your application.` : noKnownFindings ? 'OSV returned no known advisory for the checked versions. This is not a guarantee that the project is safe.' : checking ? 'TRACEGUARD is checking resolved package names and versions against OSV.' : lifecycle === 'Dependency inventory ready' ? 'The dependency inventory is ready. Security advisory checking has not started yet.' : 'Some project dependencies or advisory checks could not be fully analyzed. Unknown items are not counted as clear.'}</p></div>
          <div className="result-status-actions"><span className={`scan-lifecycle scan-lifecycle-${lifecycleTone}`} role="status" aria-live="polite">{lifecycle}</span><button className="button button-secondary" disabled={checking} onClick={onCheck}>{checking ? 'Checking OSV advisories…' : report ? 'Check OSV again' : 'Check OSV advisories'}</button></div></div>
        {checking && <p className="progress-note" role="status" aria-live="polite"><span className="loading-ring" /> Checking the resolved dependency versions against OSV. No source code is sent.</p>}
        {checkError && <p className="error-banner" role="alert">{checkError} Results stay unknown until the check succeeds.</p>}
        <div className="result-counts" aria-label="Counts from this saved scan"><CountCard label="Dependency instances" value={scan.counts?.dependencyInstances ?? libraries.length} /><CountCard label="Unique packages" value={uniquePackageCount} /><CountCard label="Resolved dependencies" value={resolvedCount} /><CountCard label="Unresolved declarations" value={scan.counts?.unresolvedDeclarations ?? unresolved} /><CountCard label="Packages checked against OSV" value={report ? checkedCount ?? 0 : 'Not checked'} /><CountCard label="Package instances with matches" value={report ? matched.length : 'Not checked'} /><CountCard label="Unknown / incomplete checks" value={report ? unknown.length : 'Not checked'} /></div>
        <p className="inventory-state-line"><strong>Dependency inventory:</strong> {inventoryStatusLabel(scan.analysisStatus)} <span>·</span> <strong>Security check:</strong> {report ? report.status === 'complete' && unknown.length === 0 ? 'Complete' : report.status === 'unavailable' ? 'Unavailable' : 'Partial' : checking ? 'In progress' : 'Not started'}</p>
      </section>

      {matched.length > 0 && <section className="beginner-findings" aria-labelledby="known-findings-heading"><div className="section-title"><div><p className="eyebrow">STEP 5 · REVIEW FINDINGS</p><h2 id="known-findings-heading">Known security findings</h2><p>Each finding is a version match from an advisory source. It does not prove the affected code runs in your project.</p></div><ActionLink href={`#/scans/${scan.id}/findings`}>All package results</ActionLink></div>
        {matched.map(node => {
          const check = checks.get(node.id)!;
          return <article className="plain-finding" key={node.id}><h3>{node.name}<span className="version-label">{node.version ?? 'version unknown'}</span></h3><p className="finding-context">{node.direct ? 'Listed directly in the project' : node.transitive ? 'Included through another dependency' : 'Relationship not established'} · {node.installPath}</p>
            {check.advisoryIds.map(id => {
              const key = JSON.stringify(node.ecosystem && node.ecosystem !== 'npm' ? [id, node.name, node.ecosystem] : [id, node.name]);
              const advisory = report?.advisories?.[key]; const verified = advisory?.verification === 'verified';
              return <details className="advisory-explanation" key={id}><summary>{verified ? advisory.summary : `Security notice ${id}`} <span className="finding-id">{id}</span></summary>
                <div className="explanation-grid"><section><h4>What is wrong?</h4><p>{verified ? advisory.description || advisory.summary : 'OSV returned this advisory ID for the recorded package name and version, but TRACEGUARD could not verify the advisory details in this check.'}</p></section><section><h4>Why it matters</h4><p>{verified ? 'This version falls within the advisory’s affected package range. Whether the affected behavior is used by your application has not been established.' : 'A version match deserves review. This result alone does not show whether your code uses the affected behavior.'}</p></section><section><h4>How to address it</h4><p>{verified && advisory.fixedVersions.length ? `The advisory lists fixed versions: ${advisory.fixedVersions.join(', ')}. Check the Remediation Plan for a published candidate and compatibility review.` : 'No verified fixed version is available in this result. Generate the Remediation Plan for evidence-based next steps.'}</p></section></div>
                <p className="finding-source">{verified ? `Source severity: ${advisory.severityLabel ?? 'not provided'}.` : 'Severity and fix details are unverified.'} <a href={advisory?.source ?? `https://osv.dev/vulnerability/${encodeURIComponent(id)}`} target="_blank" rel="noreferrer">Open advisory source</a></p>
              </details>;
            })}
          </article>;
        })}
      </section>}

      {coverageGap && <section className="incomplete-checks" aria-labelledby="incomplete-heading"><p className="eyebrow">COVERAGE · SEPARATE FROM SECURITY FINDINGS</p><h2 id="incomplete-heading">Some dependencies could not be fully analyzed.</h2><p>These gaps are not counted as safe, and they do not erase findings already confirmed for other package versions.</p>
        <div className="coverage-summary-grid"><div><strong>{requiredUnresolved.length}</strong><span>Required declarations without a resolved package</span></div><div><strong>{unknown.length}</strong><span>Packages with unknown or incomplete OSV checks</span></div><div><strong>{optionalPeers.length}</strong><span>Optional peer dependencies not present</span></div></div>
        {coverageCategories.length > 0 && <div className="coverage-categories"><h3>What is incomplete?</h3><ul>{coverageCategories.map(category => <li key={category}>{category}</li>)}</ul></div>}
        {coverageFolders.length > 0 && <p><strong>Project folders affected:</strong> {coverageFolders.map(folder => <code key={folder}>{folder || '.'}</code>)}</p>}
        <p><strong>What this means:</strong> a required declaration without a resolved version cannot be checked against OSV for that version. Unknown OSV results remain unchecked. Unsupported project formats have no dependency inventory.</p>
      </section>}
      {!coverageGap && optionalPeers.length > 0 && <section className="optional-peer-note"><strong>{optionalPeers.length} optional peer dependencies are not installed.</strong><p>They are marked optional in project metadata and may be absent by design; they are not counted as missing required dependency versions.</p>{optionalPeerFolders.length > 0 && <p>Project folders: {optionalPeerFolders.map(folder => <code key={folder}>{folder || '.'}</code>)}</p>}</section>}

      {report && matched.length === 0 && securityComplete && <p className="safe-result-note">No known findings were returned for the checked dependency inventory. This is not a guarantee that the project is safe.</p>}

      <ReportsPanel key={scan.id} scanId={scan.id} />
      <details className="advanced-details"><summary><span><strong>Advanced details</strong><small>Dependency map, SBOM, function paths, and scan evidence</small></span></summary>
        <div className="advanced-links"><a href={`#/scans/${scan.id}/dependencies`}>Open dependency map</a>{scan.sbom && <a href={`/api/scans/${scan.id}/sbom`} download>Download software inventory (SBOM)</a>}<a href={`#/scans/${scan.id}/reachability`}>Open function-path analysis</a><a href={`#/scans/${scan.id}/findings`}>Open all dependency checks</a></div>
        <div className="advanced-metadata"><p><strong>Inventory:</strong> {scan.counts?.dependencyInstances ?? libraries.length} dependency instances · {uniquePackageCount} unique packages · {resolvedCount} resolved dependencies · {scan.counts?.unresolvedDeclarations ?? unresolved} unresolved declarations · {scan.counts?.dependencyEdges ?? graph?.edges.length ?? 0} recorded relationships.</p><p><strong>Repository revision:</strong> {scan.evidence?.commitSha ?? 'Not available for this ZIP or archive source'}.</p><p><strong>Analyzed formats:</strong> {(scan.ecosystems ?? []).join(', ') || 'No supported package ecosystem found'}.</p><p><strong>Source files saved for analysis:</strong> {scan.sourceFiles?.length ?? 0}. User project code was not run.</p></div>
        <details><summary>Dependency instances and versions</summary><div className="table-scroll"><table className="data-table"><thead><tr><th>Package</th><th>Version</th><th>Project file</th><th>Relationship</th><th>Security check</th></tr></thead><tbody>{libraries.map(node => <tr key={node.id}><td>{node.name}</td><td>{node.version ?? 'Not resolved'}</td><td>{node.project}</td><td>{node.direct ? 'Direct' : node.transitive ? 'Through another package' : 'Not known'}</td><td>{checks.get(node.id)?.status === 'matched' ? 'Known finding' : checks.get(node.id)?.status === 'no-known' && checks.get(node.id)?.complete ? 'No known match returned' : 'Unknown'}</td></tr>)}</tbody></table></div>{graph!.unresolved.length > 0 && <div><h3>Unresolved project declarations</h3><ul>{graph!.unresolved.map((item, index) => <li key={`${item.name}-${index}`}>{item.name} · requested {item.requested || 'version not specified'}</li>)}</ul></div>}</details>
        <details><summary>Dependency map preview</summary><DependencyGraph key={scan.id} graph={graph!} scanId={scan.id} sourceFiles={scan.sourceFiles} advisoryReport={report} onAdvisoryReport={() => onCheck()} /></details>
        {scan.evidence?.metadataHashes.length ? <details><summary>Project files read ({scan.evidence.metadataHashes.length})</summary><ul>{scan.evidence.metadataHashes.map(file => <li key={file.path}><code>{file.path}</code> · SHA-256 {file.sha256}</li>)}</ul></details> : null}
        <details><summary>Inventory notes</summary>{graph?.warnings.length ? <ul>{graph.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul> : <p>No inventory notes were recorded.</p>}</details>
        <details><summary>Full inventory and security-check messages</summary><div className="coverage-evidence-details">
          {graph?.unresolved.length ? <section><h3>Unresolved dependency declarations ({graph.unresolved.length})</h3><ul>{graph.unresolved.map((item, index) => <li key={`${item.from}-${item.name}-${index}`}><strong>{item.optionalPeer ? 'Optional peer' : item.kind}</strong> · {item.name} · requested {item.requested || 'not specified'} · folder {folderForNode(item.from)}</li>)}</ul></section> : <p>No unresolved dependency declarations.</p>}
          {graph?.warnings.length ? <section><h3>Inventory warnings</h3><ul>{graph.warnings.map((warning, index) => <li key={`${index}-${warning}`}>{warning}</li>)}</ul></section> : null}
          {scan.evidence?.projects.length ? <section><h3>Project coverage details</h3><ul>{scan.evidence.projects.map((project, index) => <li key={`${index}-${project.path}`}><strong>{project.path || '.'} · {project.manager} · {project.status}</strong>{project.reasons.length ? <ul>{project.reasons.map((reason, reasonIndex) => <li key={`${reasonIndex}-${reason}`}>{reason}</li>)}</ul> : <p>No project-specific coverage warnings.</p>}</li>)}</ul></section> : null}
          {report?.warnings.length ? <section><h3>OSV and security-check messages</h3><ul>{report.warnings.map((warning, index) => <li key={`${index}-${warning}`}>{warning}</li>)}</ul></section> : null}
          {report && <section><h3>Per-package security-check records</h3><ul>{report.checks.filter(check => unknown.some(node => node.id === check.nodeId)).map(check => { const node = libraries.find(item => item.id === check.nodeId); return <li key={check.nodeId}>{node?.name ?? check.nodeId}@{node?.version ?? 'version unresolved'} · {check.status} · complete: {String(check.complete)}{check.advisoryIds.length ? ` · advisories: ${check.advisoryIds.join(', ')}` : ''}</li>; })}</ul></section>}
        </div></details>
      </details>
      {scan?.graph && <RescanPanel key={`rescan-${scan.id}`} scan={scan} />}
      <Panel title="Recent scans" subtitle="Saved scans in this workspace" action={<TextLink href="#/scans">View all scans</TextLink>}><HistoryTable scans={scans} compact /></Panel>
    </>}
  </>;
}
function CountCard({ label, value }: { label: string; value: number | string }) { return <div className="result-count-card"><strong>{value}</strong><span>{label}</span></div>; }
function inventoryStatusLabel(status: ScanResult['analysisStatus']) {
  if (status === 'analyzed') return 'Complete for recognized project files';
  if (status === 'unsupported') return 'Unsupported project format';
  if (status === 'unknown') return 'No supported dependency inventory';
  if (status === 'failed') return 'Failed';
  return 'Partial';
}
function RadarIcon() { return <ScanLine size={24} />; }

export function FindingsPage({ scan, report, checking, error, onCheck, analyses = {} }: { scan: ScanResult; report?: VulnerabilityReport; checking: boolean; error: string; onCheck: () => void; analyses?: Record<string, ReachabilityReport> }) {
  const [query, setQuery] = useState(''); const [status, setStatus] = useState('all'); const [severity, setSeverity] = useState('all'); const [sort, setSort] = useState('severity');
  const [remediation, setRemediation] = useState<ReportBundle>(); const [remediationBusy, setRemediationBusy] = useState(false); const [remediationError, setRemediationError] = useState('');
  useEffect(() => { let current = true; void fetch(`/api/scans/${scan.id}/reports`).then(async response => response.ok ? response.json() as Promise<ReportBundle> : undefined).then(bundle => { if (current && bundle?.scanId === scan.id) setRemediation(bundle); }).catch(() => { /* A report may not have been generated yet. */ }); return () => { current = false; }; }, [scan.id]);
  async function checkUpdateOptions() {
    setRemediationBusy(true); setRemediationError('');
    try { const response = await fetch(`/api/scans/${scan.id}/reports`, { method: 'POST' }); const bundle = await response.json(); if (!response.ok) throw new Error(bundle.error ?? 'Update options could not be verified.'); setRemediation(bundle as ReportBundle); }
    catch (cause) { setRemediationError(cause instanceof Error ? cause.message : 'Update options could not be verified.'); }
    finally { setRemediationBusy(false); }
  }
  const checks = new Map(report?.checks.map(c => [c.nodeId, c]) ?? []);
  const nodes = scan.graph?.nodes.filter(n => !n.isProject) ?? [];
  const matchedNodes = nodes.filter(node => checks.get(node.id)?.status === 'matched');
  const uniqueAdvisories = new Set(matchedNodes.flatMap(node => checks.get(node.id)?.advisoryIds ?? []));
  const labels = [...new Set(matchedNodes.flatMap(node => (checks.get(node.id)?.advisoryIds ?? []).map(id => getAdvisory(report, id, node.name, node.ecosystem)?.severityLabel).filter((label): label is string => !!label)))].sort();
  const rows = nodes.map(node => {
    const check = checks.get(node.id); const status = check?.status === 'matched' ? 'matched' : check?.complete ? check.status : 'unknown';
    const entries = (check?.advisoryIds ?? []).map(id => ({ id, detail: getAdvisory(report, id, node.name, node.ecosystem) }));
    const searchText = `${node.name} ${node.version ?? ''} ${node.installPath} ${entries.map(({ id, detail }) => `${id} ${detail?.aliases.join(' ') ?? ''} ${detail?.summary ?? ''}`).join(' ')}`.toLowerCase();
    const ranked = entries.reduce((rank, entry) => Math.min(rank, severityRank(entry.detail?.verification === 'verified' ? entry.detail.severityLabel : undefined)), 99);
    return { node, check, status, entries, searchText, ranked };
  }).filter(row => (status === 'all' || row.status === status) && (severity === 'all' || row.entries.some(({ detail }) => detail?.verification === 'verified' && detail.severityLabel === severity)) && row.searchText.includes(query.toLowerCase()));
  rows.sort((a, b) => sort === 'package-desc' ? b.node.name.localeCompare(a.node.name) : sort === 'package-asc' ? a.node.name.localeCompare(b.node.name) : sort === 'severity' ? a.ranked - b.ranked || a.node.name.localeCompare(b.node.name) : b.entries.length - a.entries.length || a.node.name.localeCompare(b.node.name));
  const unknownCount = nodes.filter(node => !checks.get(node.id)?.complete || checks.get(node.id)?.status === 'unknown').length;
  return <><PageHeading eyebrow="SCAN RESULTS / SECURITY FINDINGS" title="Security findings" description="Review advisory matches for each installed package version. A match does not prove that your application uses the affected behavior." action={<button className="button" disabled={checking} onClick={onCheck}><RefreshCw size={16} />{checking ? 'Checking security database…' : 'Check security findings'}</button>} />
    <div className="finding-totals"><div><strong>{matchedNodes.length}</strong><span>Affected package instances</span></div><div><strong>{uniqueAdvisories.size}</strong><span>Unique advisory IDs</span></div><div><strong>{unknownCount}</strong><span>Packages with unknown checks</span></div><p>Duplicate installed versions count as separate package instances. Advisory IDs count once even when they affect several instances.</p></div>
    {!report && <div className="info-banner"><ShieldCheck size={19} /><p>Run an advisory check to load current OSV results. Package names and resolved versions are checked; source files stay in this workspace.</p></div>}{error && <p role="alert" className="error-banner">{error}</p>}{report?.warnings.map(w => <p className="warning-banner" key={w}>{w}</p>)}
    <div className="finding-controls"><label className="search-field"><Search size={17} /><input aria-label="Search findings" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search package, version, advisory, or summary" /></label><label>Check status<select aria-label="Filter findings by status" value={status} onChange={e => setStatus(e.target.value)}><option value="all">All packages</option><option value="matched">Known findings</option><option value="no-known">No known match</option><option value="unknown">Unknown / unchecked</option></select></label><label>Severity<select aria-label="Filter findings by severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{labels.map(label => <option key={label}>{label}</option>)}</select></label><label>Sort by<select aria-label="Sort findings" value={sort} onChange={e => setSort(e.target.value)}><option value="severity">Highest severity first</option><option value="package-asc">Package name A to Z</option><option value="package-desc">Package name Z to A</option><option value="instances">Most advisories first</option></select></label><span>{rows.length} package instances</span></div>
    <div className="finding-card-list">{rows.slice(0, 200).map(({ node, check, status: checkStatus, entries }) => {
      const reachability = analyses[node.id];
      return <article className="finding-card" key={node.id}><header className="finding-card-header"><div><h2>{node.name} <span className="installed-version">{node.version ?? 'Version not resolved'}</span></h2><p>{node.ecosystem ?? 'Ecosystem not identified'} · {node.direct ? 'Direct dependency' : node.transitive ? 'Included through another dependency' : 'Relationship not known'} · <code>{node.installPath}</code></p></div><Badge tone={checkStatus === 'matched' ? 'red' : checkStatus === 'no-known' ? 'green' : 'amber'}>{checkStatus === 'matched' ? 'Known finding' : checkStatus === 'no-known' ? 'No known match' : 'Unknown'}</Badge></header>
        {checkStatus === 'matched' && entries.length ? entries.map(({ id, detail }) => {
          const verified = detail?.verification === 'verified'; const sourceSeverity = verified ? detail?.severityLabel : undefined;
          const description = detail?.description ?? ''; const title = detail?.summary ?? 'Advisory details are unavailable.';
          const concise = advisorySentences(title || description, 2);
          const impact = advisoryImpact(description, title);
          const fixed = verified ? [...new Set(detail?.fixedVersions ?? [])] : [];
          const updateAction = remediation?.remediationPlan.actions.find(action => action.packageNodeId === node.id);
          const savedReachability = remediation?.securityFindings.findings.find(finding => finding.package.id === node.id)?.reachability.report;
          const candidateAnalysis = reachability ?? savedReachability;
          const tiedAnalysis = candidateAnalysis?.target.packageNodeId === node.id && candidateAnalysis.target.advisoryId === id ? candidateAnalysis : undefined;
          const statusText = tiedAnalysis?.status ?? 'UNKNOWN';
          return <section className="finding-advisory" key={id}><div className="finding-advisory-heading"><div><p className="finding-eyebrow">ADVISORY {id}</p><h3>{id}</h3></div>{sourceSeverity && <span className={`severity-badge severity-${sourceSeverity.toLowerCase()}`}>{sourceSeverity}</span>}</div>
            <div className="finding-explanation-grid"><section><h4>What’s wrong?</h4><p>{concise || 'A version-specific advisory match was returned. Details could not be summarized from the source record.'}</p></section><section><h4>Why it matters</h4><p>{impact}</p></section><section><h4>Is my application affected?</h4><p className={`reachability-badge reachability-${statusText.toLowerCase().replaceAll(' ', '-')}`}>{statusText}</p><p className="finding-note">{tiedAnalysis ? `${tiedAnalysis.reason} This result applies only to its declared entrypoint, package export and analysis coverage.` : 'UNKNOWN — no static analysis result explicitly linked to this advisory and package instance is available.'}</p></section><section><h4>How to fix</h4>{updateAction?.status === 'VERIFIED CANDIDATE' && updateAction.suggestedVersion ? <><p>Possible update: <strong>{updateAction.suggestedVersion}</strong>. Its release exists in the package registry and had no known OSV match at the verification time.</p><p className="finding-note">Compatibility is NOT TESTED. Check your runtime constraints, release notes, parent dependency requirements and project tests before updating.</p></> : <>{fixed.length ? <p>Advisory-listed fixed version{fixed.length === 1 ? '' : 's'}: <strong>{fixed.join(', ')}</strong>.</p> : <p>{verified ? 'This advisory record does not provide a verified fixed version.' : 'A fix could not be verified from the available advisory details.'}</p>}<p className="finding-note">A fixed boundary is not a compatibility check. Verify an available candidate and test it in your project before updating.</p><button type="button" className="finding-update-button" onClick={() => void checkUpdateOptions()} disabled={remediationBusy}>{remediationBusy ? 'Checking available updates…' : 'Check for verified update options'}</button>{updateAction && <p className="finding-note">{updateAction.status === 'MANUAL REVIEW' ? 'No update candidate passed registry and advisory checks. Manual review is needed.' : updateAction.steps[0]}</p>}</>}{remediationError && <p role="alert" className="finding-note remediation-error">{remediationError}</p>}</section></div>
            <details className="technical-details"><summary>View full technical details</summary><div className="technical-body"><p><strong>Advisory status:</strong> {detail?.verification ?? 'details unavailable'}</p><p><strong>Identifiers:</strong> {[id, ...(detail?.aliases ?? [])].join(' · ')}</p><p><strong>Affected ranges from OSV:</strong></p>{detail?.affectedVersions?.length ? <ul>{detail.affectedVersions.map((range, i) => <li key={i}><code>{range}</code></li>)}</ul> : <p>OSV did not provide a formatted affected range in this response.</p>}{description ? <><h4>Complete advisory description</h4><AdvisoryMarkdown source={description} /></> : <p>Full description is not available.</p>}<div className="technical-links">{[detail?.source, ...(detail?.references ?? [])].filter((value): value is string => !!value).map((value, i) => { const href = safeHref(value); return href ? <a key={`${href}-${i}`} href={href} target="_blank" rel="noreferrer noopener">{i === 0 ? 'Open OSV advisory' : `Source reference ${i}`}</a> : null; })}</div></div></details>
          </section>;
        }) : <div className="finding-neutral"><h3>{checkStatus === 'no-known' ? 'No known match was returned' : 'This package check is unknown'}</h3><p>{checkStatus === 'no-known' ? 'OSV returned no known advisory for the recorded version at the time of this check. This is not a guarantee of safety.' : 'TRACEGUARD could not complete a version-specific advisory check. This package is not counted as clear.'}</p></div>}
        {checkStatus === 'matched' && !entries.length && <p className="finding-note">An advisory ID matched, but detailed advisory information is unavailable. Open all package checks for the recorded IDs.</p>}
        <footer className="finding-card-footer"><a href={`#/scans/${scan.id}/dependencies?node=${encodeURIComponent(node.id)}`}>View dependency map</a><a href={`#/scans/${scan.id}/reachability?node=${encodeURIComponent(node.id)}`}>Run scoped function analysis</a></footer>
      </article>;
    })}{!rows.length && <div className="table-empty">No package instances match these filters.</div>}</div>
    {rows.length > 200 && <p className="chart-footnote">Showing the first 200 package instances. Narrow the search to see more.</p>}
    <div className="boundary-note"><TriangleAlert size={20} /><div><strong>Advisory matches are not proof of exploitability</strong><p>Presence, dependency paths and scoped static function analysis are different evidence. Reachability is shown only when an actual analysis result was linked to this exact advisory and package instance.</p></div></div>
  </>;
}

function getAdvisory(report: VulnerabilityReport | undefined, id: string, name: string, ecosystem?: string) {
  if (!report?.advisories) return undefined;
  const key = JSON.stringify(ecosystem && ecosystem !== 'npm' ? [id, name, ecosystem] : [id, name]);
  return report.advisories[key];
}
function severityRank(label?: string) { return ({ CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3 } as Record<string, number>)[label?.toUpperCase() ?? ''] ?? 10; }

export function ReachabilityPage({ scan, report, selectedId, analysis, onReport }: { scan: ScanResult; report?: VulnerabilityReport; selectedId?: string; analysis: Record<string, ReachabilityReport>; onReport: (report: ReachabilityReport) => void }) {
  const [query, setQuery] = useState(''); const [choice, setChoice] = useState(selectedId ?? '');
  const nodes = scan.graph?.nodes.filter(n => !n.isProject) ?? [];
  const selected = nodes.find(n => n.id === (selectedId ?? choice));
  const checks = new Map(report?.checks.map(c => [c.nodeId, c]) ?? []);
  const filtered = nodes.filter(n => `${n.name} ${n.version ?? ''} ${n.installPath}`.toLowerCase().includes(query.toLowerCase()));
  return <><PageHeading eyebrow="ADVANCED DETAILS / SOURCE EVIDENCE" title="Function paths" description="Explore whether a declared function path reaches an affected package. This limited code analysis does not prove exploitability." /><div className="coverage-strip"><span><Fingerprint size={18} />{selected?.ecosystem === 'PyPI' ? 'PYTHON FUNCTION PATHS: UNKNOWN' : 'STATIC CALL TRAVERSAL'}</span><Badge tone="purple">{selected?.ecosystem === 'PyPI' ? 'Python analysis unsupported' : 'Choose affected function'}</Badge><Badge tone="muted">Exploitability not assessed</Badge></div>
    <div className="reachability-layout"><Panel title="Choose a package instance" subtitle={`${nodes.length} locked instances · versions remain distinct`} className="package-picker"><label className="search-field"><Search size={16} /><input aria-label="Search reachability packages" value={query} onChange={e => setQuery(e.target.value)} placeholder="Name, version, or path…" /></label><div className="package-options">{filtered.slice(0, 100).map(n => <button key={n.id} className={n.id === selected?.id ? 'package-option active' : 'package-option'} onClick={() => { setChoice(n.id); window.location.hash = `/scans/${scan.id}/reachability?node=${encodeURIComponent(n.id)}`; }}><span className="package-option-icon"><Boxes size={17} /></span><span><strong>{n.name}<small>{n.version ?? 'unresolved'}</small></strong><em>{checks.get(n.id)?.status === 'matched' ? 'Advisory match' : n.direct ? 'Direct dependency' : 'Transitive / locked'}</em><small className="instance-path">{n.installPath}</small></span><ChevronRight size={15} /></button>)}{!filtered.length && <p className="table-empty">No matching package instances.</p>}{filtered.length > 100 && <p className="chart-footnote">Showing 100 matches. Refine the search.</p>}</div></Panel>
      <div className="surface reachability-detail">{selected ? <><div className="selected-package-heading"><span className="feature-icon"><Fingerprint size={23} /></span><div><h2>{selected.name}<span className="version-label">{selected.version}</span></h2><p className="mono muted">{selected.installPath}</p></div><a className="text-link" href={`#/scans/${scan.id}/dependencies?node=${encodeURIComponent(selected.id)}`}>View graph<ArrowRight size={14} /></a></div><ReachabilityPanel key={selected.id} scanId={scan.id} node={selected} sourceFiles={scan.sourceFiles ?? []} advisoryIds={checks.get(selected.id)?.advisoryIds ?? []} initialReport={analysis[selected.id]} onReport={onReport} /></> : <EmptyState icon={<Fingerprint size={32} />} title="Follow a function's path">Select a package instance to declare an entrypoint and affected export. Source lines and analysis coverage will appear here after a real analysis request.</EmptyState>}</div>
    </div>
  </>;
}
