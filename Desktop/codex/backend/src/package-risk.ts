import type { DependencyGraph, PackageRiskReport, PackageRiskResult, SecurityFinding } from '@traceguard/shared';

const object = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);
const text = (x: unknown, max = 500) => typeof x === 'string' ? x.slice(0, max) : '';
function url(x: unknown) { try { const u = new URL(String(x)); return u.protocol === 'https:' && !u.username && !u.password ? u.href.slice(0, 2000) : undefined; } catch { return undefined; } }
// Deliberately small, versioned reference list, not a registry popularity claim.
const referenceNames = ['react', 'react-dom', 'express', 'lodash', 'axios', 'typescript', 'webpack', 'vite', 'eslint', 'prettier', 'chalk', 'commander', 'mongoose', 'next', 'jquery', 'dotenv'];
export function similarName(name: string): string | undefined {
  if (referenceNames.includes(name) || name.startsWith('@')) return undefined;
  return referenceNames.find(reference => {
    if (Math.abs(reference.length - name.length) > 1 || Math.min(reference.length, name.length) < 5) return false;
    if (reference.length === name.length) {
      const positions = [...name].map((c, i) => c !== reference[i] ? i : -1).filter(i => i >= 0);
      return positions.length === 1 || positions.length === 2 && positions[1] === positions[0] + 1 && name[positions[0]] === reference[positions[1]] && name[positions[1]] === reference[positions[0]];
    }
    const [short, long] = name.length < reference.length ? [name, reference] : [reference, name];
    for (let i = 0; i < long.length; i++) if (long.slice(0, i) + long.slice(i + 1) === short) return true;
    return false;
  });
}
async function metadata(source: string, fetcher: typeof fetch, signal: AbortSignal) {
  const response = await fetcher(source, { signal, redirect: 'error', headers: { 'User-Agent': 'TRACEGUARD' } });
  if (!response.ok || !response.body) { await response.body?.cancel(); throw new Error('Unavailable'); }
  const reader = response.body.getReader(); const chunks: Buffer[] = []; let size = 0;
  try { for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 1024 * 1024) throw new Error('Oversize'); chunks.push(Buffer.from(value)); } }
  finally { await reader.cancel(); }
  const data: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!object(data)) throw new Error('Invalid metadata');
  return data;
}
function compareIntegrity(lock?: string, registry?: string): PackageRiskResult['integrity']['comparison'] {
  if (!lock || !registry) return 'NOT COMPARABLE';
  const tokens = (value: string) => value.split(/\s+/).filter(t => /^(sha1|sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$/.test(t));
  const a = tokens(lock), b = tokens(registry);
  const shared = a.filter(x => b.some(y => y.split('-')[0] === x.split('-')[0]));
  if (!shared.length) return 'NOT COMPARABLE';
  const strongest = ['sha512', 'sha384', 'sha256', 'sha1'].find(algorithm => shared.some(x => x.startsWith(`${algorithm}-`)))!;
  return shared.filter(x => x.startsWith(`${strongest}-`)).some(x => b.includes(x)) ? 'MATCH' : 'MISMATCH';
}
export async function checkPackageRisks(graph: DependencyGraph, findings: SecurityFinding[] = [], fetcher: typeof fetch = fetch): Promise<PackageRiskReport> {
  const nodes = graph.nodes.filter(n => !n.isProject);
  const signal = AbortSignal.timeout(15_000);
  const cache = new Map<string, Record<string, unknown> | null>();
  const report: PackageRiskReport = { checkedAt: new Date().toISOString(), coverage: { total: nodes.length, metadataChecked: 0, unavailable: 0, skipped: 0 }, results: [],
    limitations: ['Heuristics are review signals, not proof of malicious intent. NO SIGNALS is not a safety guarantee. Metadata can be publisher-controlled.', 'Name similarity uses a fixed reference list v1 (react, react-dom, express, lodash, axios, typescript, webpack, vite, eslint, prettier, chalk, commander, mongoose, next, jquery, dotenv), one edit or adjacent transposition, minimum length five; scoped names are excluded. It does not cover all typosquatting or dependency confusion.', 'At most 100 unique exact package/version pairs and 1,000 instances are included, with a 15-second metadata deadline and 1 MiB response limit. Unavailable or omitted data is not clean.', 'Integrity compares recorded lock and registry digest strings only. Tarballs, installed bytes, signatures and provenance attestations are not downloaded or cryptographically verified. Matching metadata does not establish safety.', 'Provenance is registry-advertised evidence only. Missing provenance or signatures does not imply malware. Lifecycle scripts are common in legitimate packages and are never executed.', 'CONFIRMED MALICIOUS requires a fresh OSV version match and a verified, non-withdrawn MAL- advisory for the same npm package. This is an attributed source verdict, not an independent analysis; other advisory IDs and heuristics cannot confirm malware. Advisory detail coverage limits also apply.'],
    sources: ['https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md', 'https://docs.npmjs.com/viewing-package-provenance/', 'https://docs.npmjs.com/cli/v11/commands/npm-audit/', 'https://osv.dev/'] };
  for (const node of nodes.slice(0, 1000)) {
    const result: PackageRiskResult = { nodeId: node.id, name: node.name, version: node.version, classification: 'UNKNOWN', metadataStatus: 'skipped', signals: [], maliciousSources: [], integrity: { lock: node.integrity, comparison: 'NOT COMPARABLE', artifactVerification: 'NOT PERFORMED' }, provenance: { status: 'UNKNOWN', signatures: [], verification: 'NOT PERFORMED' }, reviewSteps: [] };
    if (node.ecosystem && node.ecosystem !== 'npm') {
      result.reviewSteps.push('PyPI supply-chain metadata, artifact integrity and provenance checks are not implemented. npm heuristics do not apply; this coverage is UNKNOWN.');
      report.results.push(result); report.coverage.skipped++; continue;
    }
    const similar = similarName(node.name);
    if (similar) result.signals.push({ code: 'NAME_SIMILARITY', explanation: 'Name differs by one edit or adjacent transposition from a reference package. Verify the intended dependency; legitimate names can collide.', evidence: `${node.name} resembles ${similar}` });
    const key = JSON.stringify([node.name, node.version]);
    if (node.version && /^(?:@[a-zA-Z0-9_.~-]+\/)?[a-zA-Z0-9_.~-]+$/.test(node.name) && (!node.resolved || node.resolved.startsWith('https://registry.npmjs.org/')) && (cache.has(key) || cache.size < 100)) {
      result.source = `https://registry.npmjs.org/${encodeURIComponent(node.name)}/${encodeURIComponent(node.version)}`;
      if (!cache.has(key)) {
        try { const data = await metadata(result.source, fetcher, signal); cache.set(key, data.name === node.name && data.version === node.version ? data : null); }
        catch { cache.set(key, null); }
      }
      const data = cache.get(key);
      result.metadataStatus = data ? 'available' : 'unavailable';
      if (data) {
        const dist = object(data.dist) ? data.dist : {};
        const scripts = object(data.scripts) ? data.scripts : {};
        const lifecycleScripts = Object.fromEntries(['preinstall', 'install', 'postinstall'].filter(k => typeof scripts[k] === 'string').map(k => [k, text(scripts[k], 2000)]));
        result.metadata = { description: text(data.description), license: text(data.license), repository: url(object(data.repository) ? text(data.repository.url).replace(/^git\+/, '') : data.repository), homepage: url(data.homepage), maintainers: Array.isArray(data.maintainers) ? data.maintainers.filter(object).map(m => text(m.name, 100)).slice(0, 30) : [], deprecated: text(data.deprecated) || undefined, lifecycleScripts };
        result.integrity.registry = text(dist.integrity, 2000) || undefined;
        result.integrity.shasum = text(dist.shasum, 100) || undefined;
        result.integrity.comparison = compareIntegrity(node.integrity, result.integrity.registry);
        const attestationUrl = object(dist.attestations) ? url(dist.attestations.url) : undefined;
        result.provenance = { status: attestationUrl ? 'ADVERTISED' : 'NOT ADVERTISED', url: attestationUrl, verification: 'NOT PERFORMED', signatures: Array.isArray(dist.signatures) ? dist.signatures.filter(object).slice(0, 10).map(s => ({ keyid: text(s.keyid), sig: text(s.sig, 2000) })) : [] };
        if (Object.keys(lifecycleScripts).length) result.signals.push({ code: 'INSTALL_SCRIPT', explanation: 'Install lifecycle commands may execute during installation; review their purpose. Presence alone is not malicious.', evidence: Object.keys(lifecycleScripts).join(', ') });
        if (result.integrity.comparison === 'MISMATCH') result.signals.push({ code: 'INTEGRITY_MISMATCH', explanation: 'Lock and registry digests disagree for a shared algorithm. Investigate stale or modified metadata before installing; no artifact was verified.', evidence: 'Recorded lock digest differs from registry digest' });
      }
    }
    result.maliciousSources = findings.filter(f => f.package.id === node.id).flatMap(f => f.advisories.filter(a => a.verification === 'verified' && /^MAL-[A-Za-z0-9-]+$/.test(a.id)).map(a => a.source));
    result.classification = result.maliciousSources.length ? 'CONFIRMED MALICIOUS' : result.signals.length ? 'SUSPICIOUS' : result.metadataStatus === 'available' ? 'NO SIGNALS' : 'UNKNOWN';
    if (result.classification === 'CONFIRMED MALICIOUS') result.reviewSteps.push('Review the cited malware advisory and affected version immediately. Stop installing this release, remove or replace it, and assess prior execution and exposed credentials in an incident review.');
    else if (result.signals.length) result.reviewSteps.push('Verify the intended package name, owning dependency path, repository and maintainer identity. Review the recorded signal evidence before installation; do not automatically substitute a similarly named package.');
    if (result.integrity.comparison === 'MISMATCH') result.reviewSteps.push('Investigate the lockfile source and registry metadata, then verify tarball integrity in a trusted environment before regenerating a lockfile.');
    result.reviewSteps.push('In a trusted development environment, use npm audit signatures to verify supported registry signatures and provenance. This report has not performed that verification.');
    if (result.metadataStatus !== 'available') result.reviewSteps.push('Resolve missing metadata or custom/private registry coverage and repeat the check.');
    report.results.push(result);
    if (result.metadataStatus === 'available') report.coverage.metadataChecked++;
    else if (result.metadataStatus === 'unavailable') report.coverage.unavailable++;
    else report.coverage.skipped++;
  }
  report.coverage.skipped += nodes.length - report.results.length;
  return report;
}
