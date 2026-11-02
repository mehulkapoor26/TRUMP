import { useEffect, useState, type FormEvent } from 'react';
import type { ScanResult } from '@traceguard/shared';

function explainError(message: string) {
  const lower = message.toLowerCase();
  if (lower.includes('supported dependency metadata') || lower.includes('no recognized')) return 'I could not find project files TRACEGUARD can read. Add the project manifest or lockfile, or upload a ZIP for npm, Python, Maven, or a supported Gradle lockfile.';
  if (lower.includes('compressed-size limit') || lower.includes('zip exceeds')) return `${message} Remove large generated folders such as node_modules, then try again.`;
  if (lower.includes('expanded-size') || lower.includes('per-entry') || lower.includes('compression-ratio')) return `${message} Remove generated or installed files from the ZIP and try again.`;
  if (lower.includes('file-count limit')) return `${message} Remove generated files or split the repository into smaller project ZIPs.`;
  if (lower.includes('inspection timed out')) return `${message} Remove large generated folders or try a smaller ZIP.`;
  return message;
}

export function ScanForm({ onComplete }: { onComplete?: (scan: ScanResult) => void } = {}) {
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'github' | 'zip'>('github');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [maxZipBytes, setMaxZipBytes] = useState(10 * 1024 * 1024);
  useEffect(() => {
    const controller = new AbortController();
    void fetch('/api/scans/limits', { signal: controller.signal }).then(response => response.ok ? response.json() : null).then(data => {
      if (Number.isSafeInteger(data?.compressedBytes) && data.compressedBytes > 0) setMaxZipBytes(data.compressedBytes);
    }).catch(() => { /* Keep the default until the scanner is available. */ });
    return () => controller.abort();
  }, []);
  const maxZipMiB = Number((maxZipBytes / (1024 * 1024)).toFixed(1));

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(''); setResult(null);
    if (mode === 'github' && !url.trim()) { setError('Paste a public GitHub repository link first.'); return; }
    if (mode === 'zip' && (!file || !/\.zip$/i.test(file.name))) { setError('Choose a ZIP file that contains your project.'); return; }
    if (mode === 'zip' && file!.size > maxZipBytes) { setError(`This ZIP is larger than the current ${maxZipMiB} MiB upload limit. Remove generated or installed files, or upload a smaller project ZIP.`); return; }
    setBusy(true);
    try {
      const form = new FormData(); if (file) form.append('archive', file);
      const response = await fetch('/api/scans', mode === 'github'
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url.trim() }) }
        : { method: 'POST', body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(explainError(data.error ?? 'The project could not be scanned.'));
      setResult(data); onComplete?.(data);
    } catch (cause) { setError(explainError(cause instanceof Error ? cause.message : 'The scanner could not be reached. Try again or upload a ZIP.')); }
    finally { setBusy(false); }
  }

  return <section className="scanner-panel mb-8 rounded-2xl border border-slate-800 bg-slate-900 p-7" aria-labelledby="scan-project-title">
    <h2 id="scan-project-title" className="text-xl font-semibold">Scan your project</h2>
    <p className="mt-2 text-sm text-slate-300">Add a public GitHub project or upload a ZIP. TRACEGUARD reads project files without running their code.</p>
    <form onSubmit={submit} className="mt-6 space-y-4">
      <p className="font-medium">Step 1 · Choose how to add your project</p>
      <label className="block">Project source
        <select aria-label="Project source" disabled={busy} value={mode} onChange={event => setMode(event.target.value as 'github' | 'zip')} className="mt-2 block w-full rounded border border-slate-700 bg-slate-950 p-3"><option value="github">Paste a public GitHub link</option><option value="zip">Upload a ZIP file</option></select>
      </label>
      {mode === 'github'
        ? <label className="block">Public GitHub link<input aria-label="Public GitHub link" disabled={busy} required type="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://github.com/owner/project" className="mt-2 block w-full rounded border border-slate-700 p-3" /><small className="mt-1 block text-slate-400">Use the main repository link. Private repositories and branch links are not supported.</small></label>
        : <label className="block">ZIP file (up to {maxZipMiB} MiB)<input aria-label={`ZIP file (up to ${maxZipMiB} MiB)`} disabled={busy} required type="file" accept=".zip,application/zip" onChange={event => setFile(event.target.files?.[0] ?? null)} className="mt-2 block w-full rounded border border-slate-700 p-3" /><small className="mt-1 block text-slate-400">For faster uploads, leave out installed packages and generated files.</small></label>}
      <p className="font-medium">Step 2 · Start the scan</p>
      <button disabled={busy} className="rounded-lg bg-emerald-400 px-5 py-3 font-semibold text-slate-950 disabled:opacity-50">{busy ? 'Scanning your project…' : 'Scan My Project'}</button>
    </form>
    {busy && <div className="mt-5 rounded-lg border border-sky-800 bg-sky-950/50 p-4" role="status" aria-live="polite"><p className="font-medium">Processing repository</p><p className="mt-1 text-sm text-slate-300">TRACEGUARD is retrieving the public repository or safely reading your ZIP and building its dependency inventory. The API completes these steps together, so progress is shown as processing until the saved inventory is returned. No project scripts are run.</p><progress className="mt-3 w-full" aria-label="Repository processing in progress" /></div>}
    {error && <p role="alert" className="mt-5 rounded-lg border border-rose-900 bg-rose-950/40 p-4 text-rose-200"><strong className="mr-2">Failed</strong>{error}</p>}
    {result && <p role="status" className="mt-5 text-emerald-300">Dependency inventory ready. Opening project results…</p>}
  </section>;
}
