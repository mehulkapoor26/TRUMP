import { useEffect, useState } from 'react';
import type { ReportBundle } from '@traceguard/shared';
import { PackageRiskPanel } from './PackageRiskPanel';
import { Panel } from './ui';

export function ReportsPanel({ scanId }: { scanId: string }) {
  const [bundle, setBundle] = useState<ReportBundle>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/scans/${scanId}/reports`, { signal: controller.signal }).then(async response => {
      if (response.status === 404) return;
      if (!response.ok) throw new Error('Saved reports could not be loaded.');
      setBundle(await response.json());
    }).catch(error => { if (!controller.signal.aborted) setError(String(error.message)); });
    return () => controller.abort();
  }, [scanId]);
  async function generate() {
    setBusy(true); setError('');
    try {
      const response = await fetch(`/api/scans/${scanId}/reports`, { method: 'POST' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? 'Could not generate reports.');
      setBundle(data);
    } catch (error) { setError(error instanceof Error ? error.message : 'Could not generate reports.'); }
    finally { setBusy(false); }
  }
  return <Panel title="Download reports" subtitle="Get a shareable summary of findings and suggested next steps" action={<button className="button" onClick={() => void generate()} disabled={busy}>{busy ? 'Preparing reports…' : bundle ? 'Refresh reports' : 'Create reports'}</button>}>
    <div style={{ padding: 22 }}>
      <p className="page-description">Security Findings explains what matched a security notice and why it matters. Remediation Plan lists verified update candidates when available and other steps to review. A suggested update is not tested for compatibility.</p>
      <p className="page-description">Reports use this scan’s saved dependency inventory and security-check results. Create them to download PDF or JSON copies.</p>
      {error && <p role="alert" className="error-banner">{error}</p>}
      {bundle && <><p className="page-description" role="status">Report coverage: {bundle.securityFindings.coverage.status}. {bundle.securityFindings.coverage.matched} package instances matched known notices; {bundle.securityFindings.coverage.unknown} could not be checked completely.</p>
        <div aria-label="Suggested updates and review steps"><h3>Suggested next steps</h3>{bundle.remediationPlan.actions.length ? <ul>{bundle.remediationPlan.actions.map(action => <li key={action.findingId}><strong>{action.packageName}@{action.installedVersion ?? 'version unknown'}</strong> — {action.status === 'VERIFIED CANDIDATE' ? `Possible update: ${action.suggestedVersion}.` : 'Needs manual review.'} Compatibility has not been tested.</li>)}</ul> : <p>No update suggestions were verified for this scan. Review the report’s manual steps.</p>}</div>
        {(['security-findings', 'remediation-plan'] as const).map(type => <div key={type} style={{ marginTop: 18 }}><strong>{type === 'security-findings' ? 'Security Findings' : 'Remediation Plan'}</strong><p className="page-description">{type === 'security-findings' ? 'What matched, why it matters, and where the evidence came from.' : 'Possible updates and checks to perform before changing your project.'}</p><div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, marginTop: 10 }}>{['pdf', 'json'].map(format => <a className="text-link" key={format} href={`/api/scans/${scanId}/reports/${type}/${format}`} download>Download {type === 'security-findings' ? 'Security Findings' : 'Remediation Plan'} ({format.toUpperCase()})</a>)}</div></div>)}
        {bundle.securityFindings.packageRisk && <PackageRiskPanel report={bundle.securityFindings.packageRisk} />}
        <details style={{ marginTop: 20 }}><summary>What these reports cannot prove</summary><ul>{bundle.securityFindings.limitations.map((limit, i) => <li key={i} className="page-description">{limit}</li>)}</ul></details>
      </>}
    </div>
  </Panel>;
}
