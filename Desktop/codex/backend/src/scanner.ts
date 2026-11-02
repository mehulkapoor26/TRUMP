import yauzl from 'yauzl';
import CRC32 from 'crc-32';
import { randomUUID } from 'node:crypto';
import { mkdir, writeFile, readFile, readdir, stat, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ScanResult, ScanFile, SourceSnapshot, ScanSummary } from '@traceguard/shared';

const MiB = 1024 * 1024;
function limit(name: string, fallback: number, ceiling: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be a positive integer.`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) throw new Error(`${name} must be between 1 and ${ceiling}.`);
  return value;
}
export const SCAN_LIMITS = Object.freeze({
  compressedBytes: limit('TRACEGUARD_MAX_ZIP_BYTES', 10 * MiB, 100 * MiB),
  expandedBytes: limit('TRACEGUARD_MAX_EXPANDED_BYTES', 50 * MiB, 500 * MiB),
  fileCount: limit('TRACEGUARD_MAX_FILES', 5_000, 50_000),
  inspectionMs: limit('TRACEGUARD_INSPECTION_TIMEOUT_MS', 15_000, 120_000),
});
export const MAX_ZIP = SCAN_LIMITS.compressedBytes;
const MAX_TOTAL = SCAN_LIMITS.expandedBytes;
const MAX_FILES = SCAN_LIMITS.fileCount;
const INSPECTION_TIMEOUT = SCAN_LIMITS.inspectionMs;
const MAX_ENTRY = 10 * MiB;
const readableBytes = (bytes: number) => `${Number((bytes / MiB).toFixed(1))} MiB`;
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git', '__MACOSX', '.venv', 'venv', '__pycache__', 'site-packages', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox', '.gradle', 'target', 'dist', 'build', 'coverage']);
import { ScanError } from './errors.js';
import { parseDependencies, type NpmDocument } from './dependencies.js';
import { generateSbom } from './sbom.js';
import { parsePythonDependencies, type PythonDocument } from './python-dependencies.js';
import { parseJavaDependencies, type JavaDocument } from './java-dependencies.js';
import { digest, canonicalizeGraph, attachInventory, extraMetadata } from './inventory.js';
export { ScanError } from './errors.js';
export function githubRepository(input: unknown): { owner: string; repo: string; url: string } {
  if (typeof input !== 'string' || input.length > 300) throw new ScanError('Enter a public GitHub repository URL.');
  const match = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9_.-]{1,100})\/?$/.exec(input);
  if (!match || ['.', '..'].includes(match[2])) throw new ScanError('Use https://github.com/owner/repository without a query, fragment, or branch path.');
  const repo = match[2].replace(/\.git$/, '');
  if (!repo || repo === '.' || repo === '..') throw new ScanError('Invalid repository name.');
  return { owner: match[1], repo, url: `https://github.com/${match[1]}/${repo}` };
}

async function boundedResponse(response: Response, max: number): Promise<Buffer> {
  if (!response.ok) {
    await response.body?.cancel();
    if (response.status === 429 || response.status === 403 && (response.headers.get('x-ratelimit-remaining') === '0' || response.headers.has('retry-after'))) {
      const retry = response.headers.get('retry-after');
      const reset = Number(response.headers.get('x-ratelimit-reset'));
      const seconds = retry && /^\d+$/.test(retry) ? Number(retry) : retry && Number.isFinite(Date.parse(retry)) ? Math.ceil((Date.parse(retry) - Date.now()) / 1000) : reset > 0 ? Math.ceil(reset - Date.now() / 1000) : 60;
      const wait = Math.max(1, Math.min(86400, seconds));
      throw new ScanError(`GitHub archive downloads are rate limited. Retry in ${wait} seconds, or upload a ZIP you already downloaded. No automatic retries are made.`, 429, wait);
    }
    if (response.status === 403) throw new ScanError('GitHub denied access to this public archive. Try again later or upload a ZIP; private repositories are unsupported.', 403);
    throw new ScanError(response.status === 404 ? 'Public repository archive not found. Check the repository URL; private and empty repositories are unsupported.' : 'GitHub archive download failed. Try again later or upload a ZIP.', response.status === 404 ? 404 : 502);
  }
  if (!response.body) throw new ScanError('Empty GitHub response.', 502);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > max) throw new ScanError(`Repository archive exceeds configured compressed-size limit (${readableBytes(max)}). Upload a ZIP within the limit or select a smaller public repository.`, 413);
      chunks.push(Buffer.from(value));
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks);
}

export function archiveCommit(buffer: Buffer): string | undefined {
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i--) if (buffer.readUInt32LE(i) === 0x06054b50 && i + 22 + buffer.readUInt16LE(i + 20) === buffer.length) {
    const comment = buffer.subarray(i + 22).toString('utf8'); return /^[a-f0-9]{40}$/.test(comment) ? comment : undefined;
  }
}
export async function downloadRepository(input: unknown, fetcher: typeof fetch = fetch, requestedCommit?: unknown) {
  const repository = githubRepository(input);
  if (requestedCommit !== undefined && (typeof requestedCommit !== 'string' || !/^[a-f0-9]{40}$/.test(requestedCommit))) throw new ScanError('commit must be a full lowercase 40-character Git commit SHA.');
  const options = { redirect: 'error' as const, signal: AbortSignal.timeout(30_000), headers: { 'User-Agent': 'TRACEGUARD', Accept: 'application/zip' } };
  try {
    // Public archive HEAD resolves GitHub's default branch without a REST metadata request.
    // Fixed host, no credentials/redirects/retries; archive service limits are still enforced.
    const initial = await boundedResponse(await fetcher(`https://codeload.github.com/${repository.owner}/${repository.repo}/zip/${requestedCommit ?? 'HEAD'}`, options), MAX_ZIP);
    const commitSha = archiveCommit(initial);
    if (!commitSha || requestedCommit && requestedCommit !== commitSha) throw new ScanError('GitHub archive commit could not be verified. Supply a full commit SHA or upload a ZIP with revision status unknown.', 502);
    // Resolve HEAD once, then retrieve immutable content. No retry after any failed/limited response.
    const archive = requestedCommit ? initial : await boundedResponse(await fetcher(`https://codeload.github.com/${repository.owner}/${repository.repo}/zip/${commitSha}`, options), MAX_ZIP);
    if (archiveCommit(archive) !== commitSha) throw new ScanError('GitHub archive revision mismatch.', 502);
    return { archive, source: repository.url, revision: { repositoryUrl: repository.url, commitSha } };
  } catch (error) {
    if (error instanceof ScanError) throw error;
    throw new ScanError('Could not retrieve the public GitHub archive. Try again later or upload a ZIP of the repository within the stated size limit.', 502);
  }
}

export async function inspectArchive(buffer: Buffer, documents?: NpmDocument[], sources?: SourceSnapshot, pythonDocuments?: PythonDocument[], extraDocuments?: JavaDocument[], languages?: Set<string>): Promise<ScanFile[]> {
  if (buffer.length > MAX_ZIP) throw new ScanError(`ZIP exceeds configured compressed-size limit (${readableBytes(MAX_ZIP)}).`, 413);
  const zip = await new Promise<yauzl.ZipFile>((resolve, reject) => yauzl.fromBuffer(buffer, { lazyEntries: true, strictFileNames: true, validateEntrySizes: true }, (error, archive) => error ? reject(new ScanError('Invalid ZIP archive.')) : resolve(archive!)));
  const files: ScanFile[] = [];
  const seen = new Set<string>();
  let total = 0;
  let count = 0;
  let sourceBytes = 0;
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => fail(new ScanError(`Archive inspection timed out at the configured ${INSPECTION_TIMEOUT} ms limit.`, 413)), INSPECTION_TIMEOUT);
      let stopped = false;
      const fail = (error: unknown) => { if (!stopped) { stopped = true; clearTimeout(timer); zip.close(); reject(error instanceof ScanError ? error : new ScanError('Invalid or corrupt ZIP archive.')); } };
      zip.on('error', fail);
      zip.on('end', () => { stopped = true; clearTimeout(timer); resolve(); });
      zip.on('entry', (entry: yauzl.Entry) => {
        void (async () => {
          if (++count > MAX_FILES) throw new ScanError(`Archive exceeds configured file-count limit (${MAX_FILES} entries).`, 413);
          const path = entry.fileName;
          const parts = path.replace(/\/$/, '').split('/');
          if (path.length > 1024 || /[\\\x00-\x1f\x7f:]/.test(path) || parts.some(p => !p || p === '.' || p === '..') || seen.has(path.toLowerCase())) throw new ScanError('Archive contains unsafe or duplicate paths.');
          seen.add(path.toLowerCase());
          const mode = (entry.externalFileAttributes >>> 16) & 0xf000;
          if ((entry.generalPurposeBitFlag & 1) || (mode !== 0 && mode !== 0x8000 && mode !== 0x4000)) throw new ScanError('Encrypted entries, symlinks, and special files are not supported.');
          if (entry.compressionMethod !== 0 && entry.compressionMethod !== 8) throw new ScanError('Unsupported ZIP compression.');
          total += entry.uncompressedSize;
          if (total > MAX_TOTAL || entry.uncompressedSize > MAX_ENTRY || entry.uncompressedSize / Math.max(1, entry.compressedSize) > 200) throw new ScanError(`Archive exceeds configured expanded-size limit (${readableBytes(MAX_TOTAL)}), per-entry limit (${readableBytes(MAX_ENTRY)}), or compression-ratio limit (200:1).`, 413);
          const name = parts.at(-1)!;
          const extra = extraMetadata(name);
          const language = /\.(?:[cm]?js|jsx)$/.test(name) ? 'JavaScript' : /\.tsx?$/.test(name) ? 'TypeScript' : name.endsWith('.py') ? 'Python' : name.endsWith('.java') ? 'Java' : name.endsWith('.kt') ? 'Kotlin' : name.endsWith('.rs') ? 'Rust' : name.endsWith('.go') ? 'Go' : undefined;
          if (language && !parts.some(p => IGNORED_DIRECTORIES.has(p))) languages?.add(language);
          const python = ['pyproject.toml', 'poetry.lock'].includes(name) || /^requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt$/.test(name);
          const kind = name === 'package.json' || python && name !== 'poetry.lock' || extra && !/lock/.test(name) ? 'manifest' : ['package-lock.json', 'npm-shrinkwrap.json', 'poetry.lock'].includes(name) || extra ? 'lockfile' : null;
          const ignored = parts.some(p => IGNORED_DIRECTORIES.has(p));
          const relevant = kind && !ignored;
          const sourceCandidate = !!sources && /\.(?:[cm]?js|jsx|tsx?|py|java|kt|rs|go|cs|rb|php|swift)$/.test(name) && !/\.d\.ts$/.test(name) && !ignored;
          const keepSource = sourceCandidate && sources!.files.length < 200 && entry.uncompressedSize <= 256 * 1024 && sourceBytes + entry.uncompressedSize <= 2 * 1024 * 1024;
          if (sourceCandidate && !keepSource) sources!.skipped.push({ path, reason: 'Source capture limit: 200 files, 256 KiB/file, 2 MiB total.' });
          if (relevant && entry.uncompressedSize > 2 * 1024 * 1024) throw new ScanError(`${python ? 'Python' : 'npm'} metadata file exceeds 2 MiB.`, 413);
          if (path.endsWith('/')) { if (entry.uncompressedSize !== 0) throw new ScanError('Invalid directory entry.'); zip.readEntry(); return; }
          const stream = await new Promise<import('node:stream').Readable>((resolve, reject) => zip.openReadStream(entry, (error, stream) => error ? reject(error) : resolve(stream!)));
          let size = 0; let crc = 0; const chunks: Buffer[] = [];
          for await (const chunk of stream) {
            size += chunk.length;
            if (stopped || size > entry.uncompressedSize || size > MAX_ENTRY) { stream.destroy(); throw new ScanError(`Archive exceeds configured per-entry expansion limit (${readableBytes(MAX_ENTRY)}).`, 413); }
            crc = CRC32.buf(chunk, crc);
            if (relevant || keepSource) chunks.push(chunk);
          }
          if ((crc >>> 0) !== entry.crc32 || size !== entry.uncompressedSize) throw new ScanError('Archive checksum or size mismatch.');
          if (keepSource) { sources!.files.push({ path, content: Buffer.concat(chunks).toString('utf8') }); sourceBytes += entry.uncompressedSize; }
          if (relevant) {
            const sha256 = digest(Buffer.concat(chunks));
            if (extra) {
              extraDocuments?.push({ path, content: Buffer.concat(chunks).toString('utf8') });
              files.push({ path, kind, bytes: size, sha256, ...(extra === 'java' ? { ecosystem: 'Maven' as const } : {}) });
              if (!stopped) zip.readEntry(); return;
            }
            if (python) {
              pythonDocuments?.push({ path, content: Buffer.concat(chunks).toString('utf8') });
              files.push({ path, kind, bytes: size, ecosystem: 'PyPI', sha256 });
              if (!stopped) zip.readEntry(); return;
            }
            let data: unknown;
            try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new ScanError(`Invalid JSON in ${path}.`); }
            if (!data || typeof data !== 'object' || Array.isArray(data)) throw new ScanError(`Invalid npm metadata in ${path}.`);
            documents?.push({ path, data });
            files.push({ path, kind, bytes: size, sha256, ecosystem: 'npm' });
          }
          if (!stopped) zip.readEntry();
        })().catch(fail);
      });
      zip.readEntry();
    });
  } finally { zip.close(); }
  // A source-only or unsupported repository is still a successful *coverage* result.
  // Keep one bounded source sentinel so the dashboard can say why dependencies were
  // not analyzed instead of rejecting the repository or implying it is clean.
  if (!files.length && sources?.files.length) {
    const source = sources.files[0];
    files.push({ path: source.path, kind: 'source', bytes: Buffer.byteLength(source.content), sha256: digest(Buffer.from(source.content)) });
  }
  if (!files.length) throw new ScanError('No supported dependency metadata or source files were found outside ignored directories.', 422);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

export function scanStore(directory = resolve(process.env.SCAN_DATA_DIR ?? '.traceguard/scans')) {
  async function load(id: string): Promise<ScanResult & { sourceSnapshot?: SourceSnapshot }> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) throw new ScanError('Invalid scan ID.');
    try { return JSON.parse(await readFile(resolve(directory, `${id}.json`), 'utf8')); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new ScanError('Scan not found.', 404); throw error; }
  }
  return {
    async saveComparison(comparison: import('@traceguard/shared').ScanComparison) {
      await load(comparison.after.scanId);
      const temporary = resolve(directory, `${comparison.after.scanId}.${comparison.id}.comparison.tmp`);
      await writeFile(temporary, JSON.stringify(comparison), { mode: 0o600, flag: 'wx' });
      await rename(temporary, resolve(directory, `${comparison.after.scanId}.comparison.json`));
    },
    async getComparison(id: string): Promise<import('@traceguard/shared').ScanComparison | null> {
      await load(id);
      try { return JSON.parse(await readFile(resolve(directory, `${id}.comparison.json`), 'utf8')); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
    },
    async saveReport(bundle: import('@traceguard/shared').ReportBundle) {
      await load(bundle.scanId);
      const temporary = resolve(directory, `${bundle.scanId}.${bundle.id}.report.tmp`);
      await writeFile(temporary, JSON.stringify(bundle), { mode: 0o600, flag: 'wx' });
      await rename(temporary, resolve(directory, `${bundle.scanId}.report.json`));
    },
    async getReport(id: string): Promise<import('@traceguard/shared').ReportBundle> {
      await load(id);
      try { return JSON.parse(await readFile(resolve(directory, `${id}.report.json`), 'utf8')); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new ScanError('Generate reports first.', 404); throw error; }
    },
    async saveAdvisories(id: string, report: import('@traceguard/shared').VulnerabilityReport) {
      const scan = await load(id);
      report.scanId = id; report.inventorySha256 = scan.evidence?.inventorySha256 ?? digest(JSON.stringify(scan.graph));
      report.snapshotId = digest(JSON.stringify(report));
      const temporary = resolve(directory, `${id}.${randomUUID()}.advisories.tmp`);
      await writeFile(temporary, JSON.stringify(report), { flag: 'wx', mode: 0o600 }); await rename(temporary, resolve(directory, `${id}.advisories.json`)); return report;
    },
    async getAdvisories(id: string): Promise<import('@traceguard/shared').VulnerabilityReport | null> {
      const scan = await load(id);
      try {
        const report = JSON.parse(await readFile(resolve(directory, `${id}.advisories.json`), 'utf8'));
        if (report.scanId !== id || report.inventorySha256 !== (scan.evidence?.inventorySha256 ?? digest(JSON.stringify(scan.graph)))) throw new ScanError('Saved advisory inventory mismatch.', 409);
        return report;
      } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
    },
    async create(archive: Buffer, source: string, revision?: { repositoryUrl: string; commitSha: string }): Promise<ScanResult> {
      const documents: NpmDocument[] = [];
      const pythonDocuments: PythonDocument[] = [];
      const extraDocuments: JavaDocument[] = []; const languages = new Set<string>();
      const sourceSnapshot: SourceSnapshot = { files: [], skipped: [] };
      const files = await inspectArchive(archive, documents, sourceSnapshot, pythonDocuments, extraDocuments, languages);
      const graph = parseDependencies(documents);
      const pythonGraph = parsePythonDependencies(pythonDocuments);
      graph.nodes.push(...pythonGraph.nodes); graph.edges.push(...pythonGraph.edges); graph.roots.push(...pythonGraph.roots); graph.unresolved.push(...pythonGraph.unresolved); graph.warnings.push(...pythonGraph.warnings);
      const java = parseJavaDependencies(extraDocuments);
      graph.nodes.push(...java.nodes); graph.edges.push(...java.edges); graph.roots.push(...java.roots); graph.unresolved.push(...java.unresolved); graph.warnings.push(...java.warnings);
      for (const doc of extraDocuments) if (extraMetadata(doc.path.split('/').at(-1)!) !== 'java') graph.warnings.push(`${doc.path}: unsupported dependency parser/build script; no code executed and no clean analysis inferred.`);
      if (graph.nodes.length > 10_000 || graph.edges.length + graph.unresolved.length > 50_000) throw new ScanError('Combined dependency graph exceeds inventory limits.', 413);
      canonicalizeGraph(graph);
      const id = randomUUID();
      const createdAt = new Date().toISOString();
      const sbom = generateSbom(graph, id, createdAt);
      const ecosystemOrder = ['npm', 'PyPI', 'Maven'] as const;
      const presentEcosystems = new Set(graph.nodes.map(n => n.ecosystem ?? 'npm'));
      const result: ScanResult = { id, status: 'completed', createdAt, source, files, graph, sbom, ecosystems: ecosystemOrder.filter(ecosystem => presentEcosystems.has(ecosystem)), sourceFiles: sourceSnapshot.files.map(file => ({ path: file.path, bytes: Buffer.byteLength(file.content), lines: file.content.split('\n').length })) };
      attachInventory(result, archive, [...languages], revision);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      await writeFile(resolve(directory, `${result.id}.json`), JSON.stringify({ ...result, sourceSnapshot }), { flag: 'wx', mode: 0o600 });
      return result;
    },
    async list(): Promise<ScanSummary[]> {
      let names: string[];
      try { names = (await readdir(directory)).filter(name => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$/.test(name)); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
      // Bound filesystem work and return the latest 50 records in this local workspace.
      const ranked: { name: string; modified: number }[] = [];
      for (const name of names.slice(0, 1000)) {
        try { ranked.push({ name, modified: (await stat(resolve(directory, name))).mtimeMs }); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      }
      ranked.sort((a, b) => b.modified - a.modified);
      const summaries: ScanSummary[] = [];
      for (const { name } of ranked.slice(0, 50)) {
        try {
          const scan = await load(name.slice(0, -5));
          summaries.push({ id: scan.id, source: scan.source, createdAt: scan.createdAt, status: scan.status,
            packages: scan.graph?.nodes.filter(n => !n.isProject).length ?? 0,
            relationships: scan.graph?.edges.length ?? 0, warnings: scan.graph?.warnings.length ?? 0, sourceFiles: scan.sourceFiles?.length ?? 0 });
        } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT' && !(error instanceof ScanError && error.status === 404)) throw error; }
      }
      return summaries.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },
    async get(id: string): Promise<ScanResult> {
      const { sourceSnapshot: _sources, ...result } = await load(id);
      return result;
    },
    async getSources(id: string): Promise<SourceSnapshot | null> {
      return (await load(id)).sourceSnapshot ?? null;
    },
  };
}
