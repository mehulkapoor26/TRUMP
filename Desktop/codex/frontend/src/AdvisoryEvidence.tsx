import type { VulnerabilityReport } from '@traceguard/shared';

export function AdvisoryEvidence({ ids, name, ecosystem = 'npm', report }: { ids: string[]; name: string; ecosystem?: 'npm' | 'PyPI' | 'Maven'; report?: VulnerabilityReport }) {
  return <div className="advisory-links">{ids.map(id => {
    const detail = report?.advisories?.[JSON.stringify(ecosystem !== 'npm' ? [id, name, ecosystem] : [id, name])];
    const verified = detail?.verification === 'verified';
    const cves = verified ? detail.aliases.filter(alias => /^CVE-\d{4}-\d+$/i.test(alias)) : [];
    return <div key={id} style={{ marginBottom: 12, maxWidth: 520 }}>
      <a href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`} target="_blank" rel="noreferrer">{id}</a>
      {cves.map(cve => <a style={{ display: 'block' }} key={cve} href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`} target="_blank" rel="noreferrer">{cve}</a>)}
      <small style={{ display: 'block' }}>Severity: {verified ? detail.severityLabel ?? (detail.severity.length ? 'Source CVSS vector available' : 'Not provided') : 'Unknown — details not verified'}</small>
      {verified && <details><summary>Advisory details</summary><p>{detail.summary}</p>{detail.severity.map((severity, index) => <p key={index} style={{ overflowWrap: 'anywhere' }}>{severity.type}: {severity.score}</p>)}{detail.affectedVersions?.map((value, index) => <p key={`affected-${index}`} style={{ overflowWrap: 'anywhere' }}>Affected: {value}</p>)}<p>Advisory fixed boundaries: {detail.fixedVersions.join(', ') || 'Not provided'}. Generate reports to verify published upgrade candidates.</p><small>Source-provided severity; runtime exploitability is not assessed.</small></details>}
    </div>;
  })}</div>;
}
