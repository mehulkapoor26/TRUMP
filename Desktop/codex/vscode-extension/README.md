# TRACEGUARD Dependency Watch

A TypeScript VS Code extension that watches npm dependency metadata and checks exact resolved package versions against the live [OSV API](https://google.github.io/osv.dev/post-v1-querybatch/). No backend service, API key, npm installation, or execution of project scripts is required.

## Install and use

Requires VS Code 1.95 or later on desktop or a remote extension host.

1. Run **Extensions: Install from VSIX…** from the Command Palette and select `traceguard-dependency-watch-0.1.0.vsix`.
2. Open a trusted npm workspace with `package.json` and `package-lock.json` or `npm-shrinkwrap.json`.
3. Open the Problems panel to see advisory warnings on affected lockfile entries. Click an advisory code to read its OSV record.

Alternatively:

```sh
code --install-extension artifacts/traceguard-dependency-watch-0.1.0.vsix
```

Checks run on startup and after saved metadata changes, creation, or deletion, including nested projects and multiple workspace folders. Edits invalidate previous diagnostics immediately; save all npm metadata to obtain a new result. Rapid changes are debounced, requests do not overlap, and obsolete scan results are discarded. New advisory matches trigger a notification with **Show Problems** and **Show output** actions. Repeated identical findings do not repeatedly notify. The status bar shows progress and incomplete coverage.

Command Palette commands:

- **TRACEGUARD: Check npm Dependencies** — run a fresh check.
- **TRACEGUARD: Show Dependency Check Output** — inspect timestamps and coverage warnings.

## Settings

| Setting | Default | Behavior |
| --- | --- | --- |
| `traceguard.enabled` | `true` | Enable automatic and manual dependency checks. |
| `traceguard.notifications` | `true` | Notify about new advisories and changed coverage failures. Diagnostics remain enabled when false. |
| `traceguard.debounceMs` | `1200` | Change debounce delay, from 250 to 10,000 milliseconds. |

## Coverage and privacy

Supports npm lockfile versions 1, 2, and 3, nested dependency instances, workspace links, and npm aliases. npm-shrinkwrap takes precedence over a sibling package-lock. `node_modules`, `.git`, `.traceguard`, `dist`, `build`, and `coverage` are excluded. Yarn and pnpm lockfiles are not supported.

Only package names and exact resolved versions are sent over HTTPS to `api.osv.dev`. Source code, credentials, and full manifests are never sent. Restricted Mode and virtual workspaces are unsupported; checks require workspace trust. No files are modified and no fixes are installed.

Warnings indicate known advisory version matches; they do not establish exploitability. Unresolved dependencies, missing lockfiles, malformed metadata, API failures, and paginated responses are explicitly reported as incomplete coverage. No matches is not a guarantee of safety. The batch API returns advisory IDs, so findings link to advisory details rather than guessing severity or fixed versions.

Limits: 200 metadata files, 2 MiB per file, 10 MiB per workspace folder, 1,000 unique package/version pairs per folder, and a 20-second OSV request deadline. Coverage limits appear in Problems and output.

## Build and package from this repository

Use Node.js 22.12+ and npm 10+. The extension shares its dependency parser and OSV client with the repository backend; build from the full repository.

```sh
npm ci
npm ci --prefix vscode-extension
npm run test --prefix vscode-extension
npm run package --prefix vscode-extension
```

The package command type-checks TypeScript, bundles all runtime dependencies (only VS Code's API remains external), and uses the official `vsce` packager to write `artifacts/traceguard-dependency-watch-0.1.0.vsix`. No backend process is needed after installation.

The build tool uses `@vscode/vsce` 4.1.0+ with a scoped `minimatch` 11.0.1+ override for the advisory affecting its original transitive range. Keep the extension lockfile and override together. See `docs/VERIFICATION.md` in the source repository for tested behavior and remaining manual checks.

Tests exercise live-client request construction with controlled responses, diagnostic locations, clean scans, offline/malformed/paginated results, missing locks, activation, invalidation, notification deduplication, and unsaved edits through a mocked VS Code API. An actual VS Code UI session is a separate manual verification step.
