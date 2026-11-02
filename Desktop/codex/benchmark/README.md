# TRACEGUARD scanner benchmark

This is a controlled dataset, not production scanner configuration. `expected-results.json` is the separately maintained oracle. The runner imports the existing production archive ingestion, npm/Python/Maven parsers, canonical inventory builder, and OSV matcher; it does not add fixture-specific behavior to those modules. Fixtures are zipped in memory and scanned as data. Nothing in them is installed or executed.

## Run

```sh
npm run benchmark       # deterministic, saved OSV response snapshot
npm run benchmark:live  # query current OSV; network required
npm test
npm run build
```

The frozen run is repeatable and uses response bytes saved under `snapshots/`. The live mode compares current results with frozen labels; a disagreement can reflect OSV database changes as well as scanner behavior. Live mode does not rewrite the snapshot or expected labels.

## Ground truth and interpretation

`snapshots/manifest.json` maps exact package/version queries to the captured official OSV API responses. `expected-results.json` separately records expected dependency identities, resolution/relationship state, statuses and exact advisory IDs, with advisory sources. The positive labels use real historical OSV records (including CVE-2020-14343/PyYAML and Log4Shell); records may be revised after publication. The snapshot is the response returned on **1 November 2026 Asia/Kolkata**; it is not a reconstruction of the advisory database on each advisory's publication date.

`no-osv-match-at-snapshot` is deliberately narrower than “safe”: the official query returned no advisory for that exact package/version at capture time. It is included as a negative only for snapshot-scoped OSV detection metrics. It does not establish the absence of undisclosed or unrecorded vulnerabilities. Failure, pagination, malformed lock, missing lock, unsupported, and dependency relationship unknown cases are not assigned vulnerability labels and do not enter TP/FP/FN/TN.

Metrics are over **unique labeled package/version pairs**, not fixture appearances or package instances. This avoids counting the nested monorepo's repeated lodash query as extra evidence. Dependency extraction is measured separately by expected ecosystem, name, version, relationship, and scan coverage status. It is not folded into vulnerability precision/recall.

The dataset includes JavaScript/npm vulnerable and no-known-advisory pairs, Python pinned versions, a Maven Gradle lock record, nested projects/monorepo, missing and malformed npm locks, duplicate package versions, unsupported Rust input, plus OSV failure and incomplete-pagination cases. The Gradle lock parser records versions but cannot infer edges; Maven relationships remain unknown. Requirements pins are represented as package/version records but their direct/transitive relationship remains unknown under current parser behavior.

## Layout

```text
benchmark/
  expected-results.json
  run.ts
  snapshots/
    manifest.json
    osv-querybatch-2026-11-01.json
    osv-is-number-7.0.0-2026-11-01.json
  fixtures/
    npm-vulnerable/
    npm-minimist-vulnerable/
    npm-fixed/                 # minimist 1.2.8 comparison for vulnerable 0.0.8
    python-vulnerable/
    python-fixed/
    maven-log4j/
    nested-monorepo/
    duplicate-versions/
    npm-missing-lock/
    npm-malformed-lock/
    unsupported-rust/
    osv-failure/
    osv-incomplete/
```

The fixtures are intentionally small parser inputs rather than clones of complete upstream repositories. They make individual expected records inspectable and reproducible. They do not claim broad ecosystem compatibility or represent a statistically sampled repository population.
