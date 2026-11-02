import { compareScans } from './comparison.js';
import { generateReportBundle, enrichVulnerabilityReport } from './reports.js';
import { renderReportPdf } from './report-pdf.js';
import type { ReachabilityReport } from '@traceguard/shared';
import { Router } from 'express';
import { validateSbom } from './sbom.js';
import { validateReachabilityRequest } from './reachability.js';
import { runReachability } from './reachability-runner.js';
import { checkVulnerabilities } from './vulnerabilities.js';
import multer from 'multer';
import { rateLimit } from 'express-rate-limit';
import { downloadRepository, MAX_ZIP, SCAN_LIMITS, ScanError, scanStore } from './scanner.js';

export function scanRouter(store = scanStore(), fetcher: typeof fetch = fetch) {
  const router = Router();
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  router.get('/limits', (_req, res) => res.json({ compressedBytes: SCAN_LIMITS.compressedBytes, expandedBytes: SCAN_LIMITS.expandedBytes, fileCount: SCAN_LIMITS.fileCount, inspectionMs: SCAN_LIMITS.inspectionMs }));
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_ZIP, files: 1, fields: 0, parts: 1, headerPairs: 50 } });
  let active = 0;
  router.post('/', rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many scans. Try again in one minute.' } }), (req, res, next) => {
    if (active >= 2) { res.status(503).json({ error: 'Scanner is busy. Try again shortly.' }); return; }
    active++;
    let released = false;
    // Hold the slot until all ingestion work has finished, even if the client disconnects.
    res.locals.releaseScan = () => { if (!released) { active--; released = true; } };
    next();
  }, (req, res, next) => {
    upload.single('archive')(req, res, error => {
      if (error) { res.locals.releaseScan(); next(error); } else next();
    });
  }, async (req, res, next) => {
    try {
      let archive: Buffer; let source: string; let revision: { repositoryUrl: string; commitSha: string } | undefined;
      if (req.is('multipart/form-data')) {
        if (!req.file || !/\.zip$/i.test(req.file.originalname)) throw new ScanError('Upload one .zip file in the archive field.');
        archive = req.file.buffer; source = 'ZIP upload';
      } else if (req.is('application/json')) {
        if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).some(key => !['url', 'commit'].includes(key))) throw new ScanError('Provide a JSON object containing url and optional full commit SHA.');
        ({ archive, source, revision } = await downloadRepository(req.body.url, fetcher, req.body.commit));
      } else throw new ScanError('Use application/json or multipart/form-data.', 415);
      const result = await store.create(archive, source, revision);
      res.status(201).location(`/api/scans/${result.id}`).json(result);
    } catch (error) { next(error); }
    finally { res.locals.releaseScan(); }
  });
  router.get('/', async (_req, res, next) => {
    try { res.json({ scans: await store.list(), limit: 50 }); }
    catch (error) { next(error); }
  });
  const analyses = new Map<string, ReachabilityReport[]>();
  let analysisActive = 0;
  router.post('/:id/reachability', rateLimit({ windowMs: 60_000, limit: 6, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many analysis requests. Try again later.' } }), async (req, res, next) => {
    if (analysisActive >= 2) { res.status(503).json({ error: 'Static analyzer is busy. Try again shortly.' }); return; }
    analysisActive++;
    try {
      validateReachabilityRequest(req.body);
      const result = await store.get(String(req.params.id));
      if (!result.graph) throw new ScanError('Rescan this project to generate dependency data.', 409);
      const analysis = await runReachability(await store.getSources(String(req.params.id)), result.graph, req.body);
      const previous = analyses.get(result.id) ?? [];
      analyses.set(result.id, [analysis, ...previous.filter(r => r.target.packageNodeId !== analysis.target.packageNodeId)].slice(0, 100));
      if (analyses.size > 100) analyses.delete(analyses.keys().next().value!);
      res.json(analysis);
    } catch (error) { next(error); }
    finally { analysisActive--; }
  });
  let advisoryActive = 0;
  router.post('/:id/vulnerabilities', rateLimit({ windowMs: 60_000, limit: 6, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many advisory requests. Try again later.' } }), async (req, res, next) => {
    if (advisoryActive >= 2) { res.status(503).json({ error: 'Advisory checker is busy. Try again shortly.' }); return; }
    advisoryActive++;
    try {
      const result = await store.get(String(req.params.id));
      if (!result.graph) throw new ScanError('Rescan this project to generate dependency data.', 409);
      res.json(await store.saveAdvisories(result.id, await enrichVulnerabilityReport(result.graph, await checkVulnerabilities(result.graph, fetcher), fetcher)));
    } catch (error) { next(error); }
    finally { advisoryActive--; }
  });
  router.get('/:id/vulnerabilities', async (req, res, next) => {
    try { const report = await store.getAdvisories(String(req.params.id)); if (!report) throw new ScanError('Run an advisory check first.', 404); res.json(report); } catch (error) { next(error); }
  });
  let comparisonActive = 0;
  router.post('/:id/comparison', rateLimit({ windowMs: 60_000, limit: 4, legacyHeaders: false }), async (req, res, next) => {
    if (comparisonActive) { res.status(503).json({ error: 'Comparison is busy. Try again shortly.' }); return; }
    comparisonActive++;
    try {
      if (!req.body || typeof req.body.beforeScanId !== 'string' || req.body.sameProject !== true || Object.keys(req.body).some(k => !['beforeScanId', 'sameProject'].includes(k))) throw new ScanError('Provide beforeScanId and sameProject: true after checking project identity.');
      const before = await store.get(req.body.beforeScanId);
      const after = await store.get(String(req.params.id));
      const comparison = await compareScans(before, after, fetcher);
      await store.saveComparison(comparison);
      res.status(201).json(comparison);
    } catch (error) { next(error); }
    finally { comparisonActive--; }
  });
  router.get('/:id/comparison', async (req, res, next) => {
    try {
      const comparison = await store.getComparison(String(req.params.id));
      if (!comparison) throw new ScanError('Compare scans first.', 404);
      res.set('Content-Disposition', `attachment; filename="traceguard-${comparison.after.scanId}-comparison.json"`).json(comparison);
    } catch (error) { next(error); }
  });
  let reportActive = 0;
  router.post('/:id/reports', rateLimit({ windowMs: 60_000, limit: 3, legacyHeaders: false }), async (req, res, next) => {
    if (reportActive >= 1) { res.status(503).json({ error: 'Report generator is busy. Try again shortly.' }); return; }
    reportActive++;
    try {
      const scan = await store.get(String(req.params.id));
      let snapshot = await store.getAdvisories(scan.id);
      if (!snapshot && scan.graph) snapshot = await store.saveAdvisories(scan.id, await enrichVulnerabilityReport(scan.graph, await checkVulnerabilities(scan.graph, fetcher), fetcher));
      const bundle = await generateReportBundle(scan, analyses.get(scan.id) ?? [], fetcher, snapshot ?? undefined);
      const comparison = await store.getComparison(scan.id);
      if (comparison) {
        bundle.securityFindings.comparison = comparison;
        bundle.remediationPlan.comparison = comparison;
      }
      await store.saveReport(bundle);
      res.status(201).json(bundle);
    } catch (error) { next(error); }
    finally { reportActive--; }
  });
  router.get('/:id/reports', async (req, res, next) => {
    try { res.json(await store.getReport(String(req.params.id))); } catch (error) { next(error); }
  });
  router.get('/:id/reports/:type/:format', async (req, res, next) => {
    try {
      const { type, format } = req.params;
      if (!['security-findings', 'remediation-plan'].includes(String(type)) || !['json', 'pdf'].includes(String(format))) throw new ScanError('Unknown report or format.', 404);
      const bundle = await store.getReport(String(req.params.id));
      const report = type === 'security-findings' ? bundle.securityFindings : bundle.remediationPlan;
      res.set('Content-Disposition', `attachment; filename="traceguard-${bundle.scanId}-${type}.${format}"`);
      if (format === 'json') res.type('application/json').send(JSON.stringify(report, null, 2));
      else res.type('application/pdf').send(await renderReportPdf(report));
    } catch (error) { next(error); }
  });
  router.get('/:id/sbom', async (req, res, next) => {
    try {
      const result = await store.get(req.params.id);
      if (!result.sbom) throw new ScanError('This older scan has no SBOM. Submit a new scan.', 409);
      validateSbom(result.sbom);
      res.set('Content-Disposition', `attachment; filename="traceguard-${result.id}.cdx.json"`).type('application/vnd.cyclonedx+json').send(JSON.stringify(result.sbom, null, 2));
    } catch (error) { next(error); }
  });
  router.get('/:id', async (req, res, next) => {
    try { res.set('Cache-Control', 'no-store').json(await store.get(req.params.id)); }
    catch (error) { next(error); }
  });
  return router;
}
