import { checkPackageRisks } from './package-risk.js';
import { createHash, randomUUID } from 'node:crypto';
import semver from 'semver';
import type { AdvisoryDetail, DependencyGraph, DependencyNode, ReachabilityReport, RemediationAction, ReportBundle, ReportContext, ScanResult, SecurityFinding, VulnerabilityReport } from '@traceguard/shared';
import { ScanError } from './errors.js';
import { checkVulnerabilities } from './vulnerabilities.js';
import { ecosystemOf, exactVersion, compareVersions, stableVersion, normalizePythonName, advisoryKey } from './ecosystems.js';
import { pythonReachabilityUnknown, javaReachabilityUnknown } from './reachability.js';
import { advisoryCounts } from './canonical.js';

const idPattern = /^[A-Za-z0-9_.-]{1,200}$/;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const text = (value: unknown, max = 500) => typeof value === 'string' ? value.slice(0, max) : '';
function safeUrl(value: unknown) {
  try { const url = new URL(String(value)); return url.protocol === 'https:' && !url.username && !url.password && url.href.length < 2000 ? url.href : undefined; } catch { return undefined; }
}
async function fetchJson(url: string, fetcher: typeof fetch, signal: AbortSignal, options: RequestInit = {}): Promise<Record<string, unknown>> {
  const response = await fetcher(url, { ...options, signal, redirect: 'error', headers: { 'User-Agent': 'TRACEGUARD', ...options.headers } });
  if (!response.ok || !response.body) { await response.body?.cancel(); throw new Error('Source unavailable'); }
  const reader = response.body.getReader(); let size = 0; const chunks: Buffer[] = [];
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 2 * 1024 * 1024) throw new Error('Source response limit exceeded'); chunks.push(Buffer.from(value)); }
  } finally { await reader.cancel(); }
  const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!object(value)) throw new Error('Invalid source response');
  return value;
}

async function advisoryDetail(id: string, name: string, fetcher: typeof fetch, signal: AbortSignal, ecosystem: 'npm' | 'PyPI' | 'Maven' = 'npm'): Promise<AdvisoryDetail> {
  const source = `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`;
  const detail: AdvisoryDetail = { id, source, verification: 'unavailable', summary: 'Advisory detail unavailable; the version match requires review.', description: '', aliases: [], severity: [], fixedVersions: [], references: [`https://osv.dev/vulnerability/${encodeURIComponent(id)}`] };
  if (!idPattern.test(id)) return detail;
  try {
    const data = await fetchJson(source, fetcher, signal);
    if (data.id !== id || !Array.isArray(data.affected)) return detail;
    const affected = data.affected.filter(entry => object(entry) && object(entry.package) && entry.package.ecosystem === ecosystem && typeof entry.package.name === 'string' && (ecosystem === 'PyPI' ? normalizePythonName(entry.package.name) === normalizePythonName(name) : entry.package.name === name)) as Record<string, unknown>[];
    detail.verification = data.withdrawn ? 'withdrawn' : affected.length ? 'verified' : 'package-mismatch';
    detail.summary = text(data.summary) || 'OSV advisory matches the recorded package version.';
    detail.description = text(data.details, 3000);
    detail.aliases = Array.isArray(data.aliases) ? data.aliases.filter((alias): alias is string => typeof alias === 'string' && idPattern.test(alias)).slice(0, 30) : [];
    detail.modified = text(data.modified, 100) || undefined;
    const severity = [...(Array.isArray(data.severity) ? data.severity : []), ...affected.flatMap(entry => Array.isArray(entry.severity) ? entry.severity : [])];
    detail.severity = severity.filter(s => object(s) && typeof s.type === 'string' && typeof s.score === 'string').slice(0, 10).map(s => ({ type: text(s.type, 40), score: text(s.score, 300) }));
    const labels = [object(data.database_specific) ? data.database_specific.severity : undefined, ...affected.map(entry => object(entry.ecosystem_specific) ? entry.ecosystem_specific.severity : undefined)];
    detail.severityLabel = labels.find((label): label is string => typeof label === 'string' && /^(LOW|MODERATE|MEDIUM|HIGH|CRITICAL)$/i.test(label))?.toUpperCase();
    const versions = new Set<string>();
    if (detail.verification === 'verified') for (const entry of affected) {
      if (!Array.isArray(entry.ranges)) continue;
      for (const range of entry.ranges) {
        if (!object(range) || (range.type !== 'SEMVER' && !(ecosystem !== 'npm' && range.type === 'ECOSYSTEM')) || !Array.isArray(range.events)) continue;
        for (const event of range.events) if (object(event) && typeof event.fixed === 'string' && exactVersion(ecosystem, event.fixed)) versions.add(event.fixed);
      }
    }
    detail.fixedVersions = [...versions].sort((a, b) => compareVersions(ecosystem, a, b)).slice(0, 30);
    detail.affectedVersions = affected.flatMap(entry => [...(Array.isArray(entry.versions) ? entry.versions.filter(v => typeof v === 'string').slice(0, 20).map(v => `listed version ${v}`) : []), ...(Array.isArray(entry.ranges) ? entry.ranges.filter(object).slice(0, 10).map(r => `${text(r.type, 20)}: ${JSON.stringify(r.events ?? []).slice(0, 1000)}`) : [])]).slice(0, 30);
    const references = Array.isArray(data.references) ? data.references.map(r => object(r) ? safeUrl(r.url) : undefined).filter((url): url is string => !!url) : [];
    detail.references = [...new Set([...detail.references, ...references])].slice(0, 15);
  } catch { /* Keep the unverified record explicit; never invent an advisory or fix. */ }
  return detail;
}

/** Batch matches remain separate from bounded advisory-detail coverage. */
export async function enrichVulnerabilityReport(graph: DependencyGraph, report: VulnerabilityReport, fetcher: typeof fetch = fetch): Promise<VulnerabilityReport> {
  const advisories: Record<string, AdvisoryDetail> = {};
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const signal = AbortSignal.timeout(15_000);
  const evidence = { requests: report.evidence?.requests ?? [], details: [...(report.evidence?.details ?? [])] };
  const detailFetcher: typeof fetch = async (url, options) => {
    const record: NonNullable<VulnerabilityReport['evidence']>['details'] extends (infer U)[] | undefined ? U : never = { url: String(url), checkedAt: new Date().toISOString() };
    evidence.details.push(record);
    try { const data = await fetchJson(String(url), fetcher, signal, options); record.data = data; return Response.json(data); }
    catch (error) { record.error = error instanceof Error ? error.message : String(error); throw error; }
  };
  let omitted = false;
  for (const check of report.checks) {
    const node = nodes.get(check.nodeId); if (!node || node.isProject) continue;
    for (const id of check.advisoryIds) {
      const key = advisoryKey(id, node.name, ecosystemOf(node)); if (advisories[key]) continue;
      if (Object.keys(advisories).length >= 40) { omitted = true; continue; }
      advisories[key] = await advisoryDetail(id, node.name, detailFetcher, signal, ecosystemOf(node));
    }
  }
  const warnings = [...report.warnings];
  if (omitted) warnings.push('Advisory details limited to 40 ID/package pairs. Additional version matches remain listed without CVE/severity details.');
  if (Object.values(advisories).some(detail => detail.verification !== 'verified')) warnings.push('Some advisory details are unavailable, withdrawn, or mismatched. CVE/severity data is incomplete; version matches require review.');
  const enriched = { ...report, warnings, advisories, evidence }; enriched.counts = advisoryCounts(graph, enriched); return enriched;
}

function impact(graph: DependencyGraph, node: DependencyNode): SecurityFinding['dependencyImpact'] {
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const parents = new Map<string, Set<string>>();
  for (const edge of graph.edges) { const values = parents.get(edge.to) ?? new Set<string>(); values.add(edge.from); parents.set(edge.to, values); }
  const directParents = [...(parents.get(node.id) ?? [])];
  const queue = [node.id]; const seen = new Set(queue); const next = new Map<string, string>();
  for (let i = 0; i < queue.length; i++) for (const parent of parents.get(queue[i]) ?? []) if (!seen.has(parent)) { seen.add(parent); next.set(parent, queue[i]); queue.push(parent); }
  const roots = graph.roots.filter(id => seen.has(id)); let truncated = directParents.length > 100 || roots.length > 3;
  const rootPaths = roots.slice(0, 3).map(root => {
    const path = [root]; while (path.at(-1) !== node.id && path.length < 40) { const child = next.get(path.at(-1)!); if (!child) break; path.push(child); }
    if (path.at(-1) !== node.id) truncated = true;
    return path;
  });
  return { parentCount: directParents.length, parents: directParents.slice(0, 100).map(id => { const parent = byId.get(id)!; return { id, name: parent.name, version: parent.version, installPath: parent.installPath }; }), rootPaths, truncated };
}
const npmSources = ['https://docs.npmjs.com/cli/v11/commands/npm-install/', 'https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#overrides', 'https://docs.npmjs.com/cli/v11/commands/npm-explain/'];

export async function generateReportBundle(scan: ScanResult, analyses: ReachabilityReport[], fetcher: typeof fetch = fetch, snapshot?: VulnerabilityReport): Promise<ReportBundle> {
  if (!scan.graph) throw new ScanError('This scan has no dependency inventory. Rescan before generating reports.', 409);
  const graph = scan.graph; const query = snapshot ?? await checkVulnerabilities(graph, fetcher);
  if (snapshot && (snapshot.scanId !== scan.id || snapshot.inventorySha256 !== (scan.evidence?.inventorySha256 ?? createHash('sha256').update(JSON.stringify(graph)).digest('hex')))) throw new ScanError('Advisory snapshot does not belong to this scan inventory.', 409);
  const libraries = graph.nodes.filter(node => !node.isProject); const byId = new Map(graph.nodes.map(node => [node.id, node]));
  const matches = query.checks.filter(check => check.status === 'matched' && byId.has(check.nodeId));
  const id = randomUUID(); const generatedAt = new Date().toISOString();
  const limitations = [
    'This report is a point-in-time snapshot of the saved inventory and fresh OSV queries, not a live deployment assessment.',
    'Dependency presence and advisory version matches do not prove runtime execution, attacker control, or actual exploitability.',
    'No known advisory match is not a safety guarantee. Unknown, failed, paginated, or skipped checks are not clean findings.',
    'Advisory IDs can be aliases of the same underlying issue; counts describe package instances, not distinct exploitable vulnerabilities.',
    'Details are fetched for at most 40 unique advisory IDs; at most 100 matched package instances and 20 advisory IDs per finding are included. Descriptions, references, paths and source evidence are bounded.',
    'Source-provided CVSS vectors are retained without inventing numeric scores or priorities. Withdrawn or mismatched records require manual review.',
    'A verified candidate is an advisory-listed fixed release that exists in its ecosystem registry and returns no known OSV match at verification time. It is not a guarantee of safety, compatibility, or that every relevant fix was published.',
    'At most three candidate releases per package/version are checked, for at most 20 unique pairs. If no candidate is verified, manual review is required. Major-version changes may require migration.',
    'Transitive updates require changes to the owning dependency declaration or parent. No dependency graph or lockfile is changed automatically.',
    'Only server-recorded scoped reachability results from this server process are included (latest result per instance, at most 100 instances per scan and 100 recent scans; not restored after restart). Their affected-export mappings are user-declared; NOT REACHABLE applies only within each declared coverage and is never a global safety claim.',
    'No source code, submitted package scripts, or package installation is executed while preparing these reports. Testing and release-note review remain the maintainer\'s responsibility.',
    ...(libraries.some(n => n.ecosystem === 'PyPI') ? ['Python reachability is unsupported and UNKNOWN. PyPI fix candidates require an advisory fixed boundary, a published non-yanked release and a fresh OSV query; Python/platform compatibility is NOT TESTED. npm supply-chain heuristics do not assess PyPI packages.'] : []),
    ...query.warnings,
  ];
  const detailSignal = AbortSignal.timeout(15_000); let fetchedDetails = 0;
  const detailCache = new Map<string, Record<string, unknown>>();
  const details = new Map<string, AdvisoryDetail>();
  // Share the network body by ID, while normalizing against each package separately.
  const cachedFetcher: typeof fetch = async (url, options) => {
    const key = String(url); const cached = detailCache.get(key); if (cached) return Response.json(cached);
    if (fetchedDetails >= 40) throw new Error('Advisory detail limit');
    fetchedDetails++; const data = await fetchJson(key, fetcher, detailSignal, options); detailCache.set(key, data); return Response.json(data);
  };
  for (const match of matches.slice(0, 100)) {
    const node = byId.get(match.nodeId)!;
    for (const advisoryId of match.advisoryIds.slice(0, 20)) {
      const key = advisoryKey(advisoryId, node.name, ecosystemOf(node));
      if (!details.has(key)) details.set(key, query.advisories?.[key] ?? await advisoryDetail(advisoryId, node.name, cachedFetcher, detailSignal, ecosystemOf(node)));
    }
  }
  const findings: SecurityFinding[] = matches.slice(0, 100).map((match, index) => {
    const node = byId.get(match.nodeId)!;
    const analysis = node.ecosystem && node.ecosystem !== 'npm' ? (node.ecosystem === 'Maven' ? javaReachabilityUnknown : pythonReachabilityUnknown)({ entrypoints: [], target: { packageNodeId: node.id, exportName: '' } }, null) : analyses.find(report => report.target.packageNodeId === node.id);
    return { id: `F-${String(index + 1).padStart(3, '0')}`, package: node,
      whatIsWrong: `OSV returned ${match.advisoryIds.length} advisory ID(s) for ${node.name}@${node.version ?? 'unresolved'} at this recorded dependency location.`,
      whyItMatters: 'The recorded dependency includes a version associated with published security advisories. Dependent packages or project roots may inherit this dependency impact. The advisory preconditions and application exposure must be evaluated separately.',
      advisories: match.advisoryIds.slice(0, 20).map(advisoryId => details.get(advisoryKey(advisoryId, node.name, ecosystemOf(node)))!), dependencyImpact: impact(graph, node),
      reachability: analysis ? { status: analysis.status, report: analysis } : { status: 'NOT ANALYZED' }, exploitability: 'NOT ASSESSED' };
  });
  const verificationSignal = AbortSignal.timeout(15_000); const verified = new Map<string, { version?: string; registrySource?: string }>();
  for (const finding of findings) {
    const node = finding.package; const key = JSON.stringify([ecosystemOf(node), node.name, node.version]);
    if (verified.has(key)) continue;
    if (verified.size >= 20) break;
    const result: { version?: string; registrySource?: string } = {}; verified.set(key, result);
    const check = query.checks.find(c => c.nodeId === node.id)!;
    if (node.ecosystem === 'Maven') continue; // Maven release ordering/publication verification is not implemented; manual review only.
    if (!check.complete || finding.advisories.length !== check.advisoryIds.length || finding.advisories.some(a => a.verification !== 'verified') || !node.version || !exactVersion(ecosystemOf(node), node.version) || !/^(?:@[a-zA-Z0-9_.~-]+\/)?[a-zA-Z0-9_.~-]+$/.test(node.name)) continue;
    const currentVersion = node.version; const ecosystem = ecosystemOf(node);
    const candidates = [...new Set(finding.advisories.flatMap(a => a.fixedVersions))].filter(v => compareVersions(ecosystem, v, currentVersion) > 0 && stableVersion(ecosystem, v)).sort((a, b) => ecosystem === 'PyPI' ? compareVersions(ecosystem, a, b) : Number(semver.major(a) !== semver.major(currentVersion)) - Number(semver.major(b) !== semver.major(currentVersion)) || semver.compare(a, b)).slice(0, 3);
    for (const version of candidates) {
      try {
        const registrySource = ecosystem === 'PyPI' ? `https://pypi.org/pypi/${encodeURIComponent(node.name)}/${encodeURIComponent(version)}/json` : `https://registry.npmjs.org/${encodeURIComponent(node.name)}/${encodeURIComponent(version)}`;
        const metadata = await fetchJson(registrySource, fetcher, verificationSignal);
        if (ecosystem === 'PyPI') {
          if (!object(metadata.info) || typeof metadata.info.name !== 'string' || normalizePythonName(metadata.info.name) !== node.name || typeof metadata.info.version !== 'string' || !exactVersion('PyPI', metadata.info.version) || compareVersions('PyPI', metadata.info.version, version) !== 0 || !Array.isArray(metadata.urls) || !metadata.urls.some(file => object(file) && file.yanked === false && typeof file.filename === 'string')) continue;
        } else if (metadata.name !== node.name || metadata.version !== version || metadata.deprecated) continue;
        const response = await fetchJson('https://api.osv.dev/v1/querybatch', fetcher, verificationSignal, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: [{ package: { name: node.name, ecosystem }, version }] }) });
        if (!Array.isArray(response.results) || response.results.length !== 1 || !object(response.results[0])) continue;
        const candidate = response.results[0];
        if ('error' in candidate || candidate.next_page_token || (candidate.vulns !== undefined && (!Array.isArray(candidate.vulns) || candidate.vulns.length))) continue;
        result.version = version; result.registrySource = registrySource; break;
      } catch { /* Leave unverified; a failed lookup never becomes a recommendation. */ }
    }
  }
  const actions: RemediationAction[] = findings.map(finding => {
    const node = finding.package; const candidate = verified.get(JSON.stringify([ecosystemOf(node), node.name, node.version]));
    const version = candidate?.version;
    const parents = finding.dependencyImpact.parents.map(p => `${p.name}@${p.version ?? 'unresolved'}`).join(', ');
    const python = node.ecosystem === 'PyPI';
    const steps = version ? python ? [
      `Review ${node.name} ${version}, the cited PyPI advisories and your Python/platform constraints. Compatibility is NOT TESTED.`,
      `Update the owning requirements/pyproject declaration or transitive parent for ${node.project}; regenerate its lockfile in your trusted development environment. TRACEGUARD does not run pip, Poetry or build backends.`,
      'Review every locked instance, conditional dependency and environment marker; run project tests and rescan. No automatic edits or installs are performed.',
    ] : [
      `Review the cited advisories and release notes for ${node.name} ${version}; compare with installed ${node.version}. Compatibility has not been tested.`,
      ...(node.direct ? [`In ${node.project}, locate the owning package.json declaration (including aliases) and update its declared dependency to the verified candidate ${version}. Preserve the intended runtime/dev/optional role.`] : []),
      ...(node.transitive || !node.direct ? [`Trace owning parents (${parents || 'root path unresolved'}). Prefer upgrading a parent release that selects ${node.name} ${version}; no parent upgrade version has been verified. Use a root override only after verifying compatibility and reviewing the npm override rules.`] : []),
      'Regenerate the affected lockfile in your controlled development environment, review the diff, and ensure every affected installation path is replaced. Do not edit a nested node_modules copy as the fix.',
    ] : [
      'No publishable, advisory-clean upgrade candidate could be verified within the report coverage. Do not assume that latest, a fixed boundary, or an unavailable query is safe.',
      `Review the cited advisories for ${node.name}@${node.version ?? 'unresolved'}, published maintainer fixes, and all owning parent paths. Verify a compatible release before choosing an upgrade.`,
      'If no supported fix exists, evaluate removing or replacing the dependency, disabling the affected feature, or applying a maintainer-reviewed patch. These are manual options, not verified mitigations.',
    ];
    return { findingId: finding.id, packageNodeId: node.id, packageName: node.name, installedVersion: node.version, status: version ? 'VERIFIED CANDIDATE' : 'MANUAL REVIEW', ...(version ? { suggestedVersion: version } : {}),
      verification: { checkedAt: new Date().toISOString(), advisorySources: finding.advisories.map(a => a.source), ...(candidate?.registrySource ? { registrySource: candidate.registrySource } : {}), candidateAdvisoryStatus: version ? 'no-known' : 'not-verified', compatibility: 'NOT TESTED' },
      steps, validation: ['Run the project\'s actual regression, integration, and build checks in a trusted environment; resolve major-version migration requirements.', 'Rescan the updated manifests and lockfiles and rerun OSV checks for all affected instances, including duplicate versions.', python ? 'Python reachability is UNKNOWN and unsupported. Review Python source, runtime feasibility, attacker control and deployment exposure manually.' : 'Revisit scoped function reachability with verified affected-export mappings. Separately review runtime feasibility, attacker control, deployment exposure, and mitigations.'],
      recommendationSources: [...new Set([...finding.advisories.flatMap(a => a.references), ...(python ? ['https://packaging.python.org/en/latest/specifications/dependency-specifiers/', 'https://pip.pypa.io/en/stable/cli/pip_install/'] : npmSources)])],
    };
  });
  const packageRisk = await checkPackageRisks(graph, findings, fetcher);
  const includedDetailsIncomplete = findings.some(f => f.advisories.some(a => a.verification !== 'verified') || f.advisories.length < query.checks.find(c => c.nodeId === f.package.id)!.advisoryIds.length);
  const coverage: ReportContext['coverage'] = { status: matches.length > findings.length || includedDetailsIncomplete ? query.status === 'unavailable' ? 'unavailable' : 'partial' : query.status, checkedAt: query.checkedAt, packageInstances: libraries.length,
    matched: matches.length, noKnownMatch: query.checks.filter(c => c.status === 'no-known' && libraries.some(n => n.id === c.nodeId)).length, unknown: query.checks.filter(c => c.status === 'unknown' && libraries.some(n => n.id === c.nodeId)).length, findingsIncluded: findings.length, findingsOmitted: matches.length - findings.length };
  const context: ReportContext = { schemaVersion: '1.0', bundleId: id, generatedAt, advisorySnapshotId: query.snapshotId, inventoryCounts: scan.counts, scanEvidence: scan.evidence, scan: { id: scan.id, source: scan.source, createdAt: scan.createdAt, inventorySha256: scan.evidence?.inventorySha256 ?? createHash('sha256').update(JSON.stringify(graph)).digest('hex') }, coverage, limitations };
  return { id, scanId: scan.id, generatedAt, securityFindings: { ...context, reportType: 'security-findings', title: 'Security Findings', findings, inventoryWarnings: graph.warnings, packageRisk }, remediationPlan: { ...context, reportType: 'remediation-plan', title: 'Remediation Plan', actions, packageRisk,
    coverageActions: [ ...(coverage.unknown ? [`Resolve or recheck ${coverage.unknown} unknown package instance(s); this is a coverage task, not proof of a vulnerability.`] : []), ...(coverage.findingsOmitted ? [`Investigate ${coverage.findingsOmitted} omitted matched instances separately.`] : []), ...(graph.warnings.length ? ['Resolve manifest/lockfile inventory warnings and repeat the scan before treating coverage as complete.'] : []), 'Validate changes in a trusted development environment. TRACEGUARD does not execute fixes or submitted source code.' ] } };
}
