# Python repository scanning

TRACEGUARD detects Python dependency metadata in the same public GitHub archives and ZIP uploads used by the npm scanner. Mixed npm/Python repositories keep separate ecosystem identities. No Python interpreter, pip, Poetry, build backend, uploaded script or downloaded package is executed.

## Use the running website

From the existing project root, install the updated backend dependencies with `npm ci`, then start `npm run dev`. Open http://127.0.0.1:5173/#/scanner and submit a public GitHub URL or ZIP containing supported metadata.

For the repeatable controlled Python input with **live OSV and PyPI evidence**, leave the website running and use another terminal:

```sh
npm run demo:python
npm run demo:python:browser -- --open
```

The first command uploads `tests/fixtures/python/poetry/`, runs real advisory checks, validates the CycloneDX SBOM, confirms Python reachability is UNKNOWN, verifies published fix candidates, and downloads both report types in JSON/PDF. It prints the exact dashboard link. It writes its ZIP and evidence to `artifacts/python-demo/`; a nonempty `summary.json.incomplete` and nonzero exit indicate a failed check. The second command uses Chrome with no network mocks to verify findings, graph selection, the unsupported-reachability message, candidate display and a report download, then opens the dashboard on macOS.

This Poetry fixture is a controlled metadata snapshot using **real published packages and dependency ranges**. It is not an installation-ready, Poetry-generated lockfile. `app.py` deliberately raises an exception if run; TRACEGUARD only reads it. Never install or execute the deliberately outdated fixture.

## Supported formats and honest coverage

| Input | Extracted data | Relationship/version limits |
| --- | --- | --- |
| `requirements.txt`, `requirements-*.txt`, similarly named requirements variants | Distribution names, normalized PyPI identity, exact `==` pins, ranges, direct URL declarations, comments, continuations and hash-option stripping | A flat requirements/freeze list does not establish direct/transitive relationships. Non-exact specifications remain UNKNOWN. Exact pins are recorded specifications, not proof of installed versions. Hashes are not verified |
| `pyproject.toml` `[project]` | PEP 621 dependencies, optional dependencies, exact pins and unresolved ranges; dependency-group string declarations | Direct declarations are known. No version solver, build-system dependency installation, dynamic metadata execution, marker evaluation or dependency-group include expansion |
| `pyproject.toml` `[tool.poetry]` | Legacy dependencies, dev dependencies and group dependency maps | Simple numeric caret/tilde and PEP 440 ranges are supported for matching recorded lock versions; unsupported constraints stay unresolved |
| `poetry.lock` 1.x/2.x | Exact package versions, package dependency maps and stable component IDs | Direct packages come from sibling pyproject declarations; transitive packages come from unambiguous lock edges reachable from those roots. Missing roots, multiple matching versions, external sources and unsupported metadata do not produce guessed relationships |

Distribution names use PyPA normalization: lowercase, with runs of `-`, `_` and `.` normalized to `-`. Python versions use a PEP 440 parser, including epochs, prereleases, postreleases and calendar versions. npm continues to use its existing semantic-version and installation-location parser. Python local builds retain their recorded version but have unverified public registry identity and are not queried as public PyPI packages.

Supported metadata is found at any archive depth, excluding installed/environment directories (`node_modules`, `.venv`, `venv`, `site-packages`, caches and Git metadata). A Python-only requirements file or Poetry lock is enough for detection; `package.json` is not required. Source capture includes `.py` under the existing capture limits, but it is never analyzed by the JavaScript engine.

Markers, extras and Python/platform constraints are inventoried without evaluating which candidates activate on a particular machine. Poetry content hashes, artifact hashes and lock freshness are not independently verified, so the snapshot's coverage warning remains explicit. Unconnected pins or lock entries display **Unknown relationship**. A sibling requirements inventory is kept separate from a Poetry lock, rather than silently replacing its locked versions.

`-r`/`-c` includes are not expanded, and arbitrary referenced files or URLs are never fetched. Recognized requirements files already present in the archive are parsed as metadata. Private/custom index configuration, Poetry source declarations, VCS/path dependencies and direct URLs are not silently treated as verified public PyPI identity. Dynamic project dependencies, unsupported constraint expressions and incomplete inventories produce warnings or UNKNOWN checks.

Pipfile, Pipenv/uv lockfiles, Conda environments, `setup.py` execution, dependency installation and Python source reachability are not implemented. `build-system.requires` and build-backend dependencies are outside the runtime inventory; TRACEGUARD never invokes a PEP 517 backend.

## Vulnerabilities and fixes

The existing OSV batch client now sends `ecosystem: "PyPI"` for Python nodes and `npm` for npm nodes. Batching and caches include ecosystem identity so identical names/versions across registries do not collide. Exact recorded public PyPI versions are checked; missing versions and unverified source identities remain UNKNOWN.

The shared Findings page displays recorded package version, advisory IDs, CVE aliases, source severity/CVSS evidence, affected ranges and advisory fixed boundaries. Missing or unverified data is labeled explicitly. Fixed boundaries are not automatically trusted as installable fixes.

The report generator verifies a Python candidate only when:

1. The applicable, non-withdrawn advisory names the same PyPI package and supplies a fixed version.
2. The version is a stable PEP 440 release newer than the recorded version.
3. The fixed HTTPS PyPI release JSON endpoint confirms package/version identity and at least one non-yanked release file.
4. A fresh OSV lookup returns complete coverage with no known advisory matches for that candidate.

Release files are not downloaded. A candidate is **not compatibility tested** for the project's Python version, platform, dependency constraints or application behavior. Failed, yanked, withdrawn, truncated, unavailable or still-affected candidates require MANUAL REVIEW. Checks retain the existing deadlines, response limits and candidate-count limits. No manifest or lockfile is modified.

Python steps cite Python packaging/pip documentation and do not prescribe npm overrides. npm-specific typosquatting, lifecycle-script, integrity and provenance heuristics do not assess PyPI packages: their supply-chain coverage is UNKNOWN, not “no signals.”

## Reachability

**Python reachability is always UNKNOWN.** This is enforced in the shared analyzer, its process runner, reports and UI. Python targets never enter the JavaScript AST worker, and Python source files are excluded from JavaScript traversal. The interface shows an unsupported-analysis explanation instead of the JavaScript function form. Even a supplied or stale Python reachability result cannot make the report claim REACHABLE or NOT REACHABLE.

JavaScript/npm scoped analysis continues to work under its existing limitations. Advisory presence and dependency paths do not establish runtime exploitability in either language.

## SBOMs and reports

All supported formats reuse CycloneDX 1.6 schema validation, dependency graph rendering, persistence, and Security Findings/Remediation Plan PDF/JSON exports. Public Python components use `pkg:pypi/normalized-name@version`; npm purls remain `pkg:npm/...`. Components retain ecosystem, metadata location, version evidence and relationship flags. Missing versions remain versionless; incomplete metadata produces incomplete composition. Poetry/requirements locations are metadata references, not a claim about runtime installation paths.

Existing limits apply to both ecosystems: defaults are 10 MiB compressed ZIP/download, 50 MiB expanded total, 2 MiB per dependency metadata file, 5,000 archive entries, 10,000 graph components and 50,000 relationships/unresolved declarations. Compressed size, expanded total, entry count and inspection deadline are configurable with the `TRACEGUARD_MAX_ZIP_BYTES`, `TRACEGUARD_MAX_EXPANDED_BYTES`, `TRACEGUARD_MAX_FILES` and `TRACEGUARD_INSPECTION_TIMEOUT_MS` environment variables; `/api/scans/limits` returns active settings. TOML nesting is bounded to 50; requirements files are bounded to 20,000 lines. Archive paths are validated and streamed in memory, not extracted. No submitted code executes.

## Verified results

On 1 November 2026 (IST), the live controlled Poetry snapshot produced **6 packages, 2 direct, 4 transitive and 6 relationships**. OSV matched five recorded package instances and returned real PyPI advisory IDs and CVEs, including **CVE-2020-14343** for PyYAML 5.3.1. PyYAML **5.4** was verified as a published, non-yanked candidate with no known match at check time. Other candidates and manual-review outcomes are preserved in `artifacts/python-demo/summary.json`; data may change.

CycloneDX validation, UNKNOWN Python reachability, both JSON exports, both parseable PDFs and a real Chrome walkthrough passed. The suite includes controlled requirements, PEP 621, Poetry 1.x/2.x, ambiguous/malformed metadata, custom sources, namespace isolation, outages/yanked fixes, mixed npm/Python archives and the full HTTP workflow. The deterministic Python browser test mocks only its advisory response; the separate `demo:python:browser` uses real network responses.

Automatic GitHub detection also passed on the real public `pypa/sampleproject` repository. Its unpinned runtime/optional declarations remain unresolved instead of guessing versions. A separate `psf/requests` attempt was rejected by the existing archive rule for symlinks/special entries; that safety rule was preserved. Both outcomes are recorded in `artifacts/python-demo/github-*.json`. The compiled backend separately passed Python inventory, UNKNOWN reachability and candidate verification with controlled external responses (`compiled-check.json`).

Run `npm test`, `npm run test:browser`, and `npm test --prefix vscode-extension` for regressions. The existing VS Code watcher still watches npm metadata only; this Python addition is to repository/ZIP scanning, not an expanded extension promise.

Parser behavior follows [PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/), [pyproject metadata](https://packaging.python.org/en/latest/specifications/pyproject-toml/) and [Poetry dependency declarations](https://python-poetry.org/docs/pyproject/). OSV documents [PyPI name/version queries](https://google.github.io/osv.dev/post-v1-query/).
