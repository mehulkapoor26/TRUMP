import PDFDocument from 'pdfkit';
import type { SecurityFindingsReport, RemediationPlanReport } from '@traceguard/shared';

/** Render every report field, including verification evidence and coverage limits. */
export function renderReportPdf(report: SecurityFindingsReport | RemediationPlanReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48, size: 'A4', info: { Title: report.title, Author: 'TRACEGUARD' } });
    const chunks: Buffer[] = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const clean = (value: string) => value.replace(/[^\x20-\x7E\n\r\t]/g, '?');
    const label = (key: string) => key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase());
    doc.font('Helvetica-Bold').fontSize(22).text(report.title);
    doc.moveDown().font('Helvetica').fontSize(10).text('TRACEGUARD | Evidence snapshot');
    if (report.coverage.status !== 'complete') doc.moveDown().text('INCOMPLETE COVERAGE: unknown checks must be investigated.');
    if ('findings' in report && !report.findings.length) doc.moveDown().text('No advisory matches were included. This is not a safety guarantee; review coverage below.');
    if ('actions' in report && !report.actions.length) doc.moveDown().text('No finding-specific remediation actions. Review coverage tasks and limitations.');
    function render(value: unknown, depth = 0) {
      if (Array.isArray(value)) {
        if (!value.length) doc.font('Helvetica').fontSize(9).text('(none recorded)');
        value.forEach((item, i) => { doc.moveDown(0.4); doc.font('Helvetica-Bold').fontSize(9).text(`${i + 1}.`); render(item, depth + 1); });
      } else if (value && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) {
          doc.moveDown(0.5).font('Helvetica-Bold').fontSize(depth === 0 ? 12 : 9).text(label(key));
          render(item, depth + 1);
        }
      } else {
        // Break long identifiers/URLs so text cannot extend beyond the page.
        const content = clean(String(value ?? 'Not recorded')).replace(/\S{75,}/g, word => word.match(/.{1,65}/g)!.join(' '));
        doc.font('Helvetica').fontSize(9).text(content, { lineGap: 2 });
      }
    }
    render(report);
    doc.end();
  });
}
