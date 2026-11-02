import { readFile } from 'node:fs/promises';
import { ZipFile } from 'yazl';
import { once } from 'node:events';

export async function publishedArchive(includeLock = true) {
  const zip = new ZipFile(); const chunks: Buffer[] = [];
  zip.outputStream.on('data', chunk => chunks.push(chunk)); const end = once(zip.outputStream, 'end');
  for (const name of ['package.json', ...(includeLock ? ['package-lock.json'] : []), 'src/entry.js']) {
    const content = await readFile(new URL(`../tests/fixtures/published-vulnerabilities/${name}`, import.meta.url));
    zip.addBuffer(content, name, { mtime: new Date('2020-01-01T00:00:00Z'), mode: 0o100644 });
  }
  zip.end(); await end; return Buffer.concat(chunks);
}
