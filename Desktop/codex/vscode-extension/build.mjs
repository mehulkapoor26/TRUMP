import { build } from 'esbuild';
await build({ entryPoints: ['src/extension.ts'], bundle: true, outfile: 'dist/extension.cjs', platform: 'node', format: 'cjs', target: 'node20', external: ['vscode'], legalComments: 'eof' });
