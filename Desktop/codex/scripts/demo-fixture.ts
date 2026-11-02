import { ZipFile } from 'yazl';
import { once } from 'node:events';

// Synthetic evidence is used only by the explicit offline judge demo and tests.
export const demoAdvisory = 'GHSA-DEMO-0001';
export async function demoArchive(version = '4.17.20') {
  const project = { name: 'traceguard-judge-fixture', version: '1.0.0', private: true, dependencies: { lodash: version }, scripts: { preinstall: 'echo DO_NOT_EXECUTE_SUBMITTED_SCRIPTS' } };
  const lock = { ...project, lockfileVersion: 3, packages: { '': project, 'node_modules/lodash': { version, resolved: `https://registry.npmjs.org/lodash/-/lodash-${version}.tgz` } } };
  const archive = new ZipFile(); const chunks: Buffer[] = [];
  archive.outputStream.on('data', chunk => chunks.push(chunk));
  const end = once(archive.outputStream, 'end');
  archive.addBuffer(Buffer.from(JSON.stringify(project, null, 2)), 'package.json');
  archive.addBuffer(Buffer.from(JSON.stringify(lock, null, 2)), 'package-lock.json');
  archive.addBuffer(Buffer.from("import lodash from 'lodash';\nexport function handler() {\n  return lodash({});\n}\n"), 'src/entry.js');
  archive.end({ comment: 'a'.repeat(40), forceZip64Format: false }); await end; return Buffer.concat(chunks);
}

export const demoFetcher: typeof fetch = async (input, options) => {
  const address = String(input);
  if (address === 'https://api.github.com/repos/traceguard-demo/fixture') return Response.json({ private: false, default_branch: 'main' });
  if (['https://codeload.github.com/traceguard-demo/fixture/zip/HEAD', `https://codeload.github.com/traceguard-demo/fixture/zip/${'a'.repeat(40)}`].includes(address)) return new Response(new Uint8Array(await demoArchive()));
  if (address === 'https://api.osv.dev/v1/querybatch') {
    const { queries } = JSON.parse(String(options?.body));
    return Response.json({ results: queries.map((q: { version: string }) => q.version === '4.17.20' ? { vulns: [{ id: demoAdvisory }] } : {}) });
  }
  if (address === `https://api.osv.dev/v1/vulns/${demoAdvisory}`) return Response.json({ id: demoAdvisory, summary: 'SIMULATED advisory for the offline judge demo', details: 'Synthetic fixture evidence, not a real vulnerability assessment.', affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] });
  if (/^https:\/\/registry\.npmjs\.org\/lodash\/4\.17\.(20|21)$/.test(address)) return Response.json({ name: 'lodash', version: address.split('/').at(-1), description: 'SIMULATED registry metadata for offline demonstration' });
  throw new Error(`Offline demo has no fixture for ${address}; no network fallback is allowed.`);
};
