# Verification record

Python extension of the repository workflow: **63 application tests, 10 npm extension tests, 3 regular Chrome tests and the offline demo Chrome test pass**. Live PyPI/OSV scanning, fix-candidate verification, PDF/JSON reports and the Python Chrome walkthrough passed. Real `pypa/sampleproject` GitHub detection passed; `psf/requests` was rejected by the existing unsafe archive-entry policy. Python reachability is explicitly UNKNOWN. See [Python support and evidence](PYTHON-SCANNING.md); earlier npm-only counts below describe the preceding verification phase.

Performed 1 November 2026, Asia/Kolkata. JSON artifacts store UTC timestamps. Environment: macOS arm64, Node.js 26.8.2, npm 11.19.1, installed Google Chrome. This is an application verification and focused security review, not a penetration-test certification.

Latest repository-workflow validation: **52 application tests and 10 extension tests pass**, plus the two regular Chrome tests, one offline demo Chrome test, and the live browser walkthrough. Real public GitHub ingestion now passes using the default-branch public archive directly. The earlier REST quota blocker below is historical and has been addressed without credentials or retrying after an archive-service limit. See [the reproducible published-vulnerability demonstration](PUBLISHED-DEMO.md) and `artifacts/published-demo/summary.json` plus `browser.json` for the latest live evidence.

## Verified

| Check | Result and evidence |
| --- | --- |
| Root automated suite | 52 passing tests: npm v1/v2/v3 parsing, graph/model and UI units, archive defenses, HTTP ingestion/persistence, SBOM validation, isolated reachability, report candidates and downloads, comparison, security routes, advisory detail/HTML handling and the real published-package fixture |
| TypeScript and builds | Root/workspace type checks and frontend/backend production builds pass |
| Existing Chrome suite | 2 passing tests: uploads, graph edges/instance selection, advisory states, scoped analysis, saved scans, navigation, charts, SBOM download and mobile overflow; advisory responses controlled |
| Judge Chrome suite | 1 passing test against the built UI: explicit simulation banner, seeded reports, PDF download, graph and advisory check |
| Clean installation | Both `npm ci` and `npm ci --prefix vscode-extension` succeeded; test/build/package checks rerun afterward |
| Extension | 10 passing tests; type checking, bundling and VSIX packaging succeed; VS Code API mocked |
| Offline repository-to-report | Synthetic GitHub transport and advisory/registry responses; real application ZIP ingestion, persistence, analysis, both PDF/JSON exports, SBOM and comparison; `artifacts/judge-demo/summary.json` |
| Compiled backend | Same controlled workflow through compiled backend and compiled child worker; `artifacts/production-check/` |
| Live ZIP-to-report | Real OSV querybatch, five advisory detail records for lodash 4.17.20, npm metadata, isolated source analysis, persisted reports and parseable PDFs; `artifacts/live-workflow/` |
| Live fix advice | Correctly remains MANUAL REVIEW when a published clean candidate cannot be verified; no version is invented |
| Dependency audits | Final root and extension lockfile audits have zero known vulnerabilities at check time; saved JSON in `artifacts/verification/`. This includes development tools and is not a guarantee against unknown issues |

The initial verification run had a nonzero `npm run test:live` exit because the GitHub REST metadata call returned HTTP 403 and `x-ratelimit-remaining: 0`. The current implementation retrieves the fixed public codeload HEAD archive directly, eliminating that unnecessary REST request. Live `expressjs/serve-static` ingestion now passes. Its absent lockfile correctly leaves dependency declarations unresolved. The controlled npm project separately verifies a complete inventory: 8 library instances, 4 direct, 4 transitive, 2 matched package instances, 6 with no known match, and 7 real advisory IDs with CVE aliases. Both report types pass JSON/PDF downloads; actual severity and advisory links render in Chrome. These results supersede the original quota limitation.

## Fixes made

- Incomplete inventories (warnings or unresolved declarations) now prevent a `complete` vulnerability coverage label, even when every recorded version lookup succeeds. Empty inventories explicitly explain why coverage is unavailable.
- Reports with more than 20 advisory IDs per finding now mark truncated evidence as partial coverage. They cannot produce a verified upgrade candidate from omitted evidence.
- `npm start` now serves the built frontend with the API, making the production/demo installation path usable without an undocumented reverse proxy.
- API responses add content-sniffing, framing and referrer headers. Cross-site browser POSTs marked by Fetch Metadata are rejected; this is a local defense, not authentication.
- Extension packager upgraded to `@vscode/vsce` 4.1.0. A scoped override selects patched `minimatch` 11.0.1+; the packager's original dependency range still selected a vulnerable release. The resulting VSIX was rebuilt and tested.
- Added a separate, labeled offline demo with no external network fallback, temporary scan storage, preflight assertions and exported evidence. Production and extension clients retain real network checks.

## Security checks exercised

Hostile GitHub URLs and extra request fields cause no outbound requests. Tests reject traversal/duplicate ZIP paths, symlinks, encrypted entries, corrupt CRCs, expansion bombs, oversized ZIPs, malformed npm data and unsafe lock paths. API tests cover malformed/oversized JSON, invalid multipart fields, scan-ID validation, cross-site POST rejection, safe errors, private record mode 0600 on POSIX, rate limiting and recovery of concurrency slots after failed ingestion. Existing tests check publisher HTML is rendered as text, API outages remain unknown, paginated results remain incomplete, source analysis does not execute submitted code, and incomplete candidate checks never imply a safe fix.

The audit command uses npm's advisory service ([npm audit documentation](https://docs.npmjs.com/cli/v11/commands/npm-audit/)). Request validation and response-header changes follow the relevant [Express security guidance](https://expressjs.com/en/advanced/best-practice-security/). The result measures known advisories and exercised controls; it is not an exhaustive security assessment.

## Incomplete or intentionally scoped

| Feature | Limit |
| --- | --- |
| GitHub live ingestion | Passed for a public Node.js repository. Private repos, branch URLs, credentials and redirect following remain unsupported; archive-service rate limits still stop retrieval |
| VS Code end-to-end | Actual VS Code extension-host installation, UI rendering and notification clicks remain manual; mocked integration tests pass |
| Vulnerability meaning | Version-advisory matching; runtime exploitability, attacker control and deployment exposure are not assessed |
| Reachability | Scoped static ESM/export-boundary analysis with user-declared target mapping. Dynamic/indirect patterns and gaps yield UNKNOWN. Dependency internals and global non-reachability are not proven |
| Upgrades | Candidate release/OSV checks are point-in-time; compatibility and project regressions are not tested; no automatic fixes |
| Registry trust | Integrity strings compared as metadata; tarball bytes, signatures and provenance are not cryptographically verified |
| Supported inventories | npm lockfiles only; Yarn/pnpm, undeclared runtime packages and platform selection are unsupported |
| Coverage limits | Inventory, source capture, network deadlines, advisory pagination, report truncation and canvas limits remain explicit; no full registry scan |
| Persistence | Scans, reports and comparisons persist locally; reachability cache is process-local and must be regenerated after restart |
| Deployment | No authentication, per-user authorization, automatic deletion policy, distributed rate limits or multi-instance coordination |
| Security review | No exhaustive fuzzing, load/soak testing, independent penetration testing or verification on every supported OS/Node version |

## Reproduce

Follow [installation and demo instructions](JUDGE-DEMO.md), then run `npm test`, `npm run test:browser`, `npm run test:demo`, `npm run test:production`, and the extension test/package commands. Run both `npm audit --json` and `npm audit --prefix vscode-extension --json` for fresh results. Live checks need network access and available third-party quotas. Preserve nonzero statuses and `incomplete` records when reporting results.
