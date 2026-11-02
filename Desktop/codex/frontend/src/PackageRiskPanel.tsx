import { useState } from 'react';
import type { PackageRiskReport } from '@traceguard/shared';

export function PackageRiskPanel({ report }: { report: PackageRiskReport }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const results = report.results.filter(r => r.name.toLowerCase().includes(query.toLowerCase()) && (filter === 'all' || r.classification === filter));
  return <section style={{ marginTop: 28 }} aria-label="Package supply chain signals">
    <h3>Package supply chain signals</h3>
    <p className="page-description">{report.results.filter(r => r.classification === 'SUSPICIOUS').length} suspicious · {report.results.filter(r => r.classification === 'CONFIRMED MALICIOUS').length} confirmed by OSV malware advisories · {report.coverage.metadataChecked}/{report.coverage.total} instances with npm metadata · {report.coverage.unavailable} unavailable · {report.coverage.skipped} skipped. Checked {new Date(report.checkedAt).toLocaleString()}.</p>
    <p className="page-description">Suspicious signals require review and do not prove malicious intent. No signals is not a safety guarantee. Artifact integrity, signatures, and provenance have not been cryptographically verified.</p>
    <div className="table-toolbar"><input aria-label="Search package risk results" placeholder="Search package name" value={query} onChange={e => setQuery(e.target.value)} /><select aria-label="Filter package risk results" value={filter} onChange={e => setFilter(e.target.value)}><option value="all">All classifications</option>{['SUSPICIOUS', 'CONFIRMED MALICIOUS', 'NO SIGNALS', 'UNKNOWN'].map(value => <option key={value}>{value}</option>)}</select></div>
    {results.slice(0, 100).map(result => <details key={result.nodeId} style={{ padding: '14px 0', borderBottom: '1px solid #253141' }}>
      <summary>{result.name}@{result.version ?? 'unresolved'} — {result.classification} · metadata {result.metadataStatus}</summary>
      <div style={{ overflowWrap: 'anywhere' }}>
        <p className="page-description">Instance: {result.nodeId}</p>
        {result.source && <a className="text-link" href={result.source} target="_blank" rel="noreferrer">npm metadata source</a>}
        {result.signals.map(signal => <p className="page-description" key={signal.code}><strong>{signal.code}: </strong>{signal.explanation} Evidence: {signal.evidence}</p>)}
        {result.maliciousSources.map(source => <p key={source}><a className="text-link" href={source} target="_blank" rel="noreferrer">OSV malware verdict source</a></p>)}
        {result.metadata && <><p className="page-description">{result.metadata.description}</p><p className="page-description">License: {result.metadata.license || 'Not recorded'} · Maintainers (informational): {result.metadata.maintainers.join(', ') || 'Not recorded'}</p>{result.metadata.repository && <p><a className="text-link" href={result.metadata.repository} target="_blank" rel="noreferrer">Publisher-declared repository</a></p>}{result.metadata.homepage && <p><a className="text-link" href={result.metadata.homepage} target="_blank" rel="noreferrer">Publisher-declared homepage</a></p>}{result.metadata.deprecated && <p className="page-description">Deprecation: {result.metadata.deprecated}</p>}<p className="page-description">Install scripts (not executed):</p><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(result.metadata.lifecycleScripts, null, 2)}</pre></>}
        <p className="page-description">Integrity comparison: {result.integrity.comparison} · artifact verification: {result.integrity.artifactVerification}</p>
        <p className="page-description">Lock digest: {result.integrity.lock ?? 'Not recorded'}<br />Registry digest: {result.integrity.registry ?? 'Not recorded'}<br />Registry SHA-1: {result.integrity.shasum ?? 'Not recorded'}</p>
        <p className="page-description">Provenance: {result.provenance.status} · verification: {result.provenance.verification}</p>
        {result.provenance.url && <a className="text-link" href={result.provenance.url} target="_blank" rel="noreferrer">Registry-advertised attestation</a>}
        <p className="page-description">Registry-advertised signatures (not verified):</p><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(result.provenance.signatures, null, 2)}</pre>
        <ul>{result.reviewSteps.map((step, i) => <li className="page-description" key={i}>{step}</li>)}</ul>
      </div>
    </details>)}
    {!results.length && <p className="page-description">No results match this filter.</p>}
    {results.length > 100 && <p className="page-description">Showing 100 results. Refine the filter; included results are available in the downloads.</p>}
    <details style={{ marginTop: 16 }}><summary>Signal methodology and limitations</summary><ul>{report.limitations.map((limit, i) => <li className="page-description" key={i}>{limit}</li>)}</ul>{report.sources.map(source => <p key={source}><a className="text-link" href={source} target="_blank" rel="noreferrer">{source}</a></p>)}</details>
  </section>;
}
