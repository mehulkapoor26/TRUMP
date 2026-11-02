# Demonstration with real published vulnerabilities

This uses a controlled npm project and **live GitHub, OSV and npm responses**. It is separate from `npm run demo`, which simulates external evidence for offline presentations.

## Run it

From the existing TRACEGUARD root, run `npm ci` if dependencies are not installed. In terminal 1:

```sh
npm run dev
```

Leave it running. Open http://127.0.0.1:5173; the API is at http://127.0.0.1:3001. Avoid editing backend source while presenting because development mode restarts the API on changes.

In terminal 2:

```sh
npm run demo:live
npm run demo:live:browser -- --open
```

The first command checks public GitHub ingestion, creates/uploads the controlled npm ZIP, queries live OSV details, validates the SBOM, runs scoped analysis, generates reports and tests missing-lock/invalid-ZIP handling. It prints the exact dashboard URL and writes evidence to `artifacts/published-demo/`. A nonzero exit means a check failed; inspect `summary.json.incomplete`. It uses the existing website and does not replace or start another server.

The second command checks that scan in headless Chrome with **no mocked network responses**, saves screenshots, tests graph selection, CVE search/status filters and a PDF download, then opens the dashboard in your default Mac browser. On macOS it uses installed Google Chrome. Set `CHROME_EXECUTABLE` for another browser path; elsewhere install Playwright Chromium. The saved scan must still exist in the same backend storage.

For a presentation without watcher restarts, use `npm run build` then `npm start` instead of `npm run dev`, and run `TRACEGUARD_URL=http://127.0.0.1:3001 npm run demo:live`. The browser command reads that URL from the saved summary. Do not run two backends on port 3001.

## Controlled input and expected results

The checked-in project is `tests/fixtures/published-vulnerabilities/`. Its npm-generated v3 lockfile contains actual published versions and registry integrity strings:

| Direct package | Locked version | Purpose |
| --- | --- | --- |
| lodash | 4.17.20 | Published advisory matches including CVE-2021-23337 |
| minimist | 0.0.8 | Published prototype-pollution advisory matches |
| is-even | 1.0.0 | Real transitive dependencies for graph/path demonstration |
| is-number | 7.0.0 | No known OSV match in the verified run |

**Do not install or execute this deliberately outdated fixture.** Its lockfile was generated using `npm install --package-lock-only --ignore-scripts --no-audit --no-fund --prefix tests/fixtures/published-vulnerabilities`. This retrieves metadata without installing fixture packages or executing scripts. The scanner streams the archive in memory; it never extracts executable files or runs submitted code.

The ZIP is built from checked-in files with fixed archive timestamps. Expected inventory: **8 library instances, 4 direct, 4 transitive and 8 relationships**. The interactive graph also includes the application root, so it has 9 nodes. The SBOM validates against the vendored CycloneDX 1.6 schema.

On 1 November 2026 (IST), live checks returned **2 matched instances, 6 with no known match, and 0 unknown library instances**. Seven OSV IDs were returned, including:

- `GHSA-35jh-r3h4-6jhm`, alias `CVE-2021-23337` (lodash).
- `GHSA-vh95-rmgr-6w4m`, alias `CVE-2020-7598` (minimist).
- `GHSA-xvch-5gv4-984h`, alias `CVE-2021-44906` (minimist).

The saved `vulnerabilities.json` contains every returned ID, alias and severity record. Advisory data can change. These counts do not establish distinct exploitable issues; aliases can describe the same underlying vulnerability. No known match is not a safety guarantee.

The Findings page now displays OSV links, CVE aliases when supplied, source severity labels and CVSS vectors under **Advisory details**. Unavailable, withdrawn or package-mismatched details stay unverified. Detail enrichment is limited to 40 ID/package pairs and a 15-second deadline. Severity values are never invented.

## Browser walkthrough

1. Open the dashboard URL printed by `npm run demo:live`. Show the dependency counts, stored reports and explicit analysis boundaries.
2. Open **Vulnerability findings** and select **Check vulnerability advisories**. Filter **Advisory matches** to see lodash/minimist. Search `CVE-2021-23337`, open its OSV/CVE links, and expand advisory details. Select **No known match** to show the other six recorded instances. Before a check, packages are unknown; failed checks retain unknown coverage.
3. Open **Dependency graph**. Search/select lodash and inspect its root/parent path. Then follow is-even's transitive dependencies. Package relationships are not execution paths.
4. Open **Function reachability**, select lodash and `src/entry.js`. The affected export `template` is a **user-declared boundary**, not an automatically proven vulnerable internal function. Entry `handler` gives REACHABLE within supported static scope. Entry `<module>` gives NOT REACHABLE within declared scope because it never invokes the handler. An empty affected-export mapping gives UNKNOWN. These are not runtime exploitability verdicts. The script records all three and generates reports after the handler analysis.
5. Return to Overview and download **Security Findings** and **Remediation Plan** in PDF and JSON. All four downloads were verified, including PDF parsing. Compatibility remains NOT TESTED. In this run, minimist had verified candidate `0.2.4`; lodash correctly required MANUAL REVIEW. Neither is a compatibility-tested fix.
6. To demonstrate the scanner manually, select ZIP and upload `artifacts/published-demo/project.zip`. This creates a new scan ID. Run its advisory check, declare scoped analysis and generate its reports; existing results belong to the original scan and are not copied.

## GitHub retrieval and rate limits

The verified public Node.js repository is `https://github.com/expressjs/serve-static`. It is downloaded through the fixed archive URL `https://codeload.github.com/expressjs/serve-static/zip/HEAD`. GitHub documents downloadable [source snapshots](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives). The tested HEAD archive resolves the default branch without a REST metadata lookup. Branches can change; the controlled ZIP is the stable demonstration inventory.

The original blocker was an exhausted anonymous REST metadata quota. GitHub's [REST rate-limit documentation](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) describes that IP-based limit. Direct public archive retrieval removes that unnecessary request. It sends no credentials, follows no redirects, performs no automatic retries and stops on archive-service limits. HTTP 429 or rate-signaled 403 returns HTTP 429 with a clear wait time and Retry-After. Ordinary access denials and missing/private archives remain errors. No authentication or limit is bypassed; no alternate-host retries occur after rejection.

The real upstream library currently has no npm lockfile. Its scan correctly reports unresolved dependencies instead of guessing versions. The controlled ZIP supplies the complete resolved inventory for vulnerability/report demonstration.

## Evidence and remaining limits

`artifacts/published-demo/` contains the ZIP, GitHub/fixture scans, validated SBOM, live advisory response, three scoped analyses, two JSON reports, two PDFs and summary. The browser check adds `browser.json`, screenshots and a UI-downloaded PDF.

Live checks depend on network access and third-party availability. Use `npm run demo` only as an explicitly labeled synthetic offline fallback. Runtime exploitability, upgrade compatibility, cryptographic provenance verification and production authentication remain outside this demonstration.
