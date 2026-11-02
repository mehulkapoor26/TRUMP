import * as vscode from 'vscode';
import { checkFiles, type MetadataFile } from './checker';

const glob = '**/{package.json,package-lock.json,npm-shrinkwrap.json}';
const exclude = '**/{node_modules,.git,.traceguard,dist,build,coverage}/**';
export function activate(context: vscode.ExtensionContext) {
  const diagnostics = vscode.languages.createDiagnosticCollection('traceguard');
  const output = vscode.window.createOutputChannel('TRACEGUARD Dependencies');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  status.command = 'traceguard.showOutput'; status.text = '$(shield) TRACEGUARD'; status.show();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let generation = 0, running: Promise<void> | undefined, disposed = false;
  let previousMatches = new Set<string>(); let previousProblem = '';
  const enabled = () => vscode.workspace.isTrusted && vscode.workspace.getConfiguration('traceguard').get('enabled', true);
  const notify = () => vscode.workspace.getConfiguration('traceguard').get('notifications', true);
  const showOutput = async () => { output.show(); };
  const warn = async (message: string) => {
    if (!notify() || disposed) return;
    const action = await vscode.window.showWarningMessage(message, 'Show Problems', 'Show output');
    if (disposed) return;
    if (action === 'Show Problems') await vscode.commands.executeCommand('workbench.actions.view.problems');
    else if (action === 'Show output') output.show();
  };

  async function scan() {
    if (running) return running;
    running = (async () => {
      let repeat = true;
      while (repeat && !disposed) {
        const revision = generation; repeat = false;
        if (!enabled()) { diagnostics.clear(); status.text = '$(shield) TRACEGUARD: disabled'; return; }
        status.text = '$(sync~spin) TRACEGUARD: checking';
        const pending = new Map<string, { uri: vscode.Uri; values: vscode.Diagnostic[] }>();
        const matches = new Set<string>(); const problems: string[] = [];
        let matched = 0, unknown = 0;
        const add = (uri: vscode.Uri, diagnostic: vscode.Diagnostic) => {
          const entry = pending.get(uri.toString()) ?? { uri, values: [] }; entry.values.push(diagnostic); pending.set(uri.toString(), entry);
        };
        for (const folder of vscode.workspace.workspaceFolders ?? []) {
          if (folder.uri.scheme !== 'file' && folder.uri.scheme !== 'vscode-remote') { problems.push(`${folder.name}: unsupported workspace filesystem.`); continue; }
          let fallback = vscode.Uri.joinPath(folder.uri, 'package.json');
          try {
            const uris = (await vscode.workspace.findFiles(new vscode.RelativePattern(folder, glob), exclude, 201)).sort((a, b) => a.path.localeCompare(b.path));
            if (!uris.length) continue;
            fallback = uris[0];
            if (uris.length > 200) throw new Error('More than 200 npm metadata files. Narrow the workspace to check all files.');
            const files: MetadataFile[] = []; const mapping = new Map<string, { uri: vscode.Uri; document: vscode.TextDocument }>(); let total = 0;
            for (const uri of uris) {
              const stat = await vscode.workspace.fs.stat(uri);
              if (stat.size > 2 * 1024 * 1024 || (total += stat.size) > 10 * 1024 * 1024) throw new Error('Metadata limit exceeded (2 MiB/file, 10 MiB/workspace folder).');
              const document = await vscode.workspace.openTextDocument(uri);
              if (document.isDirty) throw new Error('Save pending npm metadata edits before checking. Unsaved dependency changes have not been checked.');
              const path = uri.path.slice(folder.uri.path.replace(/\/$/, '').length + 1);
              const content = document.getText();
              if (Buffer.byteLength(content) > 2 * 1024 * 1024) throw new Error('Metadata text exceeds the 2 MiB file limit.');
              files.push({ path, content }); mapping.set(path, { uri, document });
            }
            const result = await checkFiles(files);
            matched += result.matched; unknown += result.unknown;
            if (result.unknown || result.warnings.length) problems.push(`${folder.name}: ${result.unknown} unknown instances; ${result.warnings.length} inventory/advisory warnings.`);
            for (const finding of result.findings) {
              const location = mapping.get(finding.path)!;
              const range = new vscode.Range(location.document.positionAt(finding.offset), location.document.positionAt(finding.offset + finding.length));
              const diagnostic = new vscode.Diagnostic(range, finding.message, finding.kind === 'advisory' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information);
              diagnostic.source = 'TRACEGUARD / OSV';
              if (finding.advisoryId) { diagnostic.code = { value: finding.advisoryId, target: vscode.Uri.parse(`https://osv.dev/vulnerability/${encodeURIComponent(finding.advisoryId)}`) }; matches.add(`${folder.uri.toString()}:${finding.key}`); }
              else diagnostic.code = 'coverage-unknown';
              add(location.uri, diagnostic);
            }
            output.appendLine(`[${result.checkedAt}] ${folder.name}: ${result.matched} matched package instances; ${result.unknown} unknown. ${result.warnings.join(' ')}`);
          } catch (error) {
            const message = `${folder.name}: dependency check incomplete: ${error instanceof Error ? error.message : String(error)}`;
            problems.push(message);
            const diagnostic = new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), message, vscode.DiagnosticSeverity.Information);
            diagnostic.source = 'TRACEGUARD'; diagnostic.code = 'check-failed'; add(fallback, diagnostic);
          }
        }
        if (disposed) return;
        if (revision !== generation) { repeat = true; continue; }
        diagnostics.clear(); for (const entry of pending.values()) diagnostics.set(entry.uri, entry.values);
        status.text = `$(shield) TRACEGUARD: ${matched} matched${problems.length ? ' · incomplete' : ''}`;
        status.tooltip = 'OSV version matches, not proof of exploitability. Open output for coverage. No known matches is not a safety guarantee.';
        const newMatches = [...matches].filter(key => !previousMatches.has(key)).length;
        previousMatches = matches;
        if (newMatches) void warn(`TRACEGUARD: ${newMatches} new advisory match(es) in saved npm metadata. See Problems for evidence; exploitability is not assessed.`);
        const problem = problems.join('\n');
        if (problem) { output.appendLine(problem); if (problem !== previousProblem) void warn('TRACEGUARD: dependency checks have incomplete coverage. See Problems and output; unchecked packages are not safe results.'); }
        previousProblem = problem;
        output.appendLine(`Completed: ${matched} matched instances, ${unknown} unknown; ${problems.length} folder coverage warning(s).`);
      }
    })();
    try { await running; } finally { running = undefined; }
  }
  function schedule() {
    generation++; diagnostics.clear();
    if (timer) clearTimeout(timer);
    if (disposed) return;
    status.text = enabled() ? '$(clock) TRACEGUARD: pending' : '$(shield) TRACEGUARD: disabled';
    const delay = Math.max(250, Math.min(10000, vscode.workspace.getConfiguration('traceguard').get('debounceMs', 1200)));
    timer = setTimeout(() => { void scan(); }, delay);
  }
  const watcher = vscode.workspace.createFileSystemWatcher(glob);
  const relevant = (uri: vscode.Uri) => !/(?:^|\/)(node_modules|\.git|\.traceguard|dist|build|coverage)(?:\/|$)/.test(vscode.workspace.asRelativePath(uri, false));
  const changed = (uri: vscode.Uri) => { if (relevant(uri)) schedule(); };
  context.subscriptions.push(diagnostics, output, status, watcher,
    watcher.onDidChange(changed), watcher.onDidCreate(changed), watcher.onDidDelete(changed),
    vscode.workspace.onDidSaveTextDocument(document => { if (/\/(package|package-lock|npm-shrinkwrap)\.json$/.test(document.uri.path)) changed(document.uri); }),
    vscode.workspace.onDidChangeTextDocument(event => { if (event.contentChanges.length && /\/(package|package-lock|npm-shrinkwrap)\.json$/.test(event.document.uri.path) && relevant(event.document.uri)) schedule(); }),
    vscode.workspace.onDidChangeWorkspaceFolders(schedule),
    vscode.workspace.onDidChangeConfiguration(event => { if (event.affectsConfiguration('traceguard')) schedule(); }),
    vscode.workspace.onDidGrantWorkspaceTrust(schedule),
    vscode.commands.registerCommand('traceguard.showOutput', showOutput),
    vscode.commands.registerCommand('traceguard.scanDependencies', async () => {
      generation++; diagnostics.clear(); if (timer) clearTimeout(timer);
      await scan();
    }),
    { dispose() { disposed = true; generation++; if (timer) clearTimeout(timer); } });
  output.appendLine('TRACEGUARD sends only npm package names and exact resolved versions to https://api.osv.dev. No submitted code or installation scripts are executed. No automatic fixes. Checks are bounded to 1,000 unique pairs; OSV requests time out after 20 seconds.');
  schedule();
  return { scanNow: async () => { generation++; if (timer) clearTimeout(timer); await scan(); } };
}
