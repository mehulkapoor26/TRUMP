# Installation and judge walkthrough

For the newly verified controlled npm project with **real published vulnerabilities**, use [the live demonstration](PUBLISHED-DEMO.md). This document also covers the distinct, explicitly synthetic offline fallback.

Run commands from the repository root, the directory containing the root `package-lock.json`. Do not edit generated `backend/dist/*.js`; edit `backend/src/*.ts` and rebuild.

## Install

Use Node.js 22.12+ and npm 10+ (this run used Node 26.8.2 and npm 11.19.1 on macOS). Internet access is needed for the initial installs. Both lockfiles must be retained: the VS Code extension is installed separately from the root workspaces.

```sh
node --version
npm --version
npm ci
npm ci --prefix vscode-extension
npm run typecheck
npm test
npm test --prefix vscode-extension
npm run build
```

## Reliable offline judge demo

```sh
npm run demo
```

Open the exact URL printed after **OFFLINE DEMO READY**, at `http://127.0.0.1:4173/#/scans/<id>/overview`. Preparation runs the entire workflow before printing the link. No internet connection is needed after installation. Set `DEMO_PORT=4174 npm run demo` if 4173 is occupied. Stop with Ctrl+C.

The top-of-page banner and scan source explicitly mark this as a simulation. ZIP parsing, dependency graphs, schema validation, isolated static analysis, persistence, comparisons, PDF rendering and HTTP downloads use real application code. GitHub downloads, OSV advisories and npm metadata use deterministic in-memory responses. `GHSA-DEMO-0001` is synthetic. The fixture does not claim lodash 4.17.21 is currently safe; the live report may correctly require manual review.

The demo uses temporary scan storage and makes no network fallback. Ctrl+C removes that temporary storage; exported evidence remains in `artifacts/judge-demo/`. Each launch replaces the exported demo files and creates fresh scan IDs. Do not run the checker and interactive demo simultaneously because they share that artifact directory.

Suggested five-minute walkthrough:

1. Open the printed link. Point out the offline banner, saved scan ID, one resolved library instance, and the saved Security Findings and Remediation Plan.
2. Download both PDF reports and JSON evidence from **Security reports**. The scripted preflight already parses both PDFs and verifies JSON downloads.
3. Open **Dependency graph**, click **Check vulnerability advisories**, and select `lodash@4.17.20`. The synthetic advisory highlights the installed instance. Dependency impact and actual exploitability remain separate.
4. Open **Function reachability**. Choose `src/entry.js`, entry export `handler`, affected export `default`, and the lodash package instance. Run **Analyze scoped reachability**. The result is a static path to a user-declared export boundary; it does not prove vulnerability exploitability.
5. Return to Overview. In **Before-and-after rescan**, choose the saved after scan using `afterScanId` from the printed summary (the fixture contains `4.17.21`), declare both scans represent the same project, then compare. The preflight's `comparison.json` has one resolved synthetic issue. Identity is user-declared, and the code never changes or installs dependencies.
6. Show `artifacts/judge-demo/summary.json`, the two ZIP inputs, CycloneDX SBOM, comparison JSON, and the four report downloads. Explain which external evidence was simulated.

For an unattended workflow check:

```sh
npm run demo:check
npm run test:production
```

The second command builds first and runs ingestion, scoped analysis and reports through the compiled backend, including its compiled child worker. Both commands stop after exporting evidence. `artifacts/production-check/` contains the compiled-run evidence.

## Real application

```sh
npm run build
npm start
```

Open `http://127.0.0.1:3001`. This serves the built frontend and API together and uses real GitHub, OSV and npm services. Development mode is `npm run dev` at `http://127.0.0.1:5173` with the API on 3001. Stop one mode before starting another on the same port.

Use **Repository scanner** with a public GitHub URL or ZIP. For a predictable live advisory check, upload `artifacts/judge-demo/before.zip` to this real application. The file contains only manifest/lock metadata and source; no package needs to be installed. The live server does not use synthetic responses. Then check advisories, declare scoped reachability if needed, and generate reports.

```sh
npm run test:live
```

This attempts public `expressjs/serve-static` ingestion and continues with a local ZIP using real OSV/npm checks. Evidence goes to `artifacts/live-workflow/`. A nonzero exit and `summary.json.incomplete` mean part of the live workflow failed. The original REST quota failure has been addressed by retrieving public default-branch archives directly, with no metadata API dependency. Actual archive-service rate limits still stop retrieval. The more complete `npm run demo:live` workflow is documented in `PUBLISHED-DEMO.md`. The product accepts neither GitHub credentials nor private repositories.

## Browser checks

On macOS, tests use installed Google Chrome. Elsewhere install Chromium and use its default Playwright executable, or set `CHROME_EXECUTABLE` to an existing browser path:

```sh
npx playwright install chromium
npm run test:browser
npm run test:demo
```

The regular browser suite uses real uploads and analysis with controlled advisory responses. The demo suite uses the built frontend and explicit offline server. Both require permission to bind loopback ports and launch a browser. Close other development servers before verification to avoid testing stale code.

## VS Code extension

```sh
npm ci --prefix vscode-extension
npm test --prefix vscode-extension
npm run package --prefix vscode-extension
code --install-extension artifacts/traceguard-dependency-watch-0.1.0.vsix
```

Alternatively open VS Code's Command Palette, select **Extensions: Install from VSIX…**, and choose the file above. Requires VS Code 1.95+ and a trusted workspace. Open a project with a saved `package.json` and npm lockfile, then run **TRACEGUARD: Check npm Dependencies**. View Problems and the **TRACEGUARD Dependencies** output channel. Save a dependency metadata change to trigger another check. The extension always uses the live OSV service and needs no backend. VS Code UI installation and real extension-host activation were not automated in this run; its watcher, diagnostics and notifications were tested through a mocked VS Code API.

The website stores scan data locally and has no authentication. Keep it on loopback for this demo. Deployment access control and retention remain unfinished.
