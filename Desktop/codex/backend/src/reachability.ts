import ts from 'typescript';
import { posix } from 'node:path';
import type { DependencyGraph, ReachabilityReport, ReachabilityRequest, SourceEvidence, SourceSnapshot } from '@traceguard/shared';
import { ScanError } from './errors.js';

export const LIMITATIONS = [
  'Syntactic, context-insensitive ESM traversal of captured JS/JSX/TS/TSX/MJS/CJS source; no code is executed.',
  'Entrypoints are user-declared. Module initialization and an optional named/default exported function are roots. Other externally invoked exports are outside coverage.',
  'Target mapping is user-declared and not verified against an advisory. A target denotes an exported API boundary, not an internal library function.',
  'External package initialization and internal code, node_modules, generated/missing source, native code, framework dispatch, callbacks, dynamic imports, CommonJS, reflection, and computed calls are not modeled.',
  'Branches are conservatively traversed without feasibility analysis. REACHABLE means a syntactic call path, not proven runtime execution or exploitability.',
  'NOT REACHABLE applies only to declared entrypoints, captured source, and the exported-boundary model. It is not evidence of application safety.',
  'Source capture: 200 files, 256 KiB/file, 2 MiB total. Traversal: 1,000 units, 5,000 calls, 100,000 AST visits; evidence limited to 100 records.',
];
export function validateReachabilityRequest(value: unknown): asserts value is ReachabilityRequest {
  if (!value || typeof value !== 'object') throw new ScanError('Provide entrypoints and a target.');
  const v = value as ReachabilityRequest;
  if (!Array.isArray(v.entrypoints) || !v.entrypoints.length || v.entrypoints.length > 10 || v.entrypoints.some(e => !e || typeof e.file !== 'string' || e.file.length > 1024 || /[\\\x00-\x1f:]/.test(e.file) || e.file.split('/').some(p => !p || p === '.' || p === '..') || typeof e.symbol !== 'string' || !/^(?:<module>|default|[A-Za-z_$][\w$]{0,99})$/.test(e.symbol))) throw new ScanError('Declare 1–10 source entrypoints with a file and <module>, default, or named export.');
  if (!v.target || typeof v.target.packageNodeId !== 'string' || v.target.packageNodeId.length > 200 || typeof v.target.exportName !== 'string' || (v.target.exportName !== '' && !/^(?:default|[A-Za-z_$][\w$]{0,99})$/.test(v.target.exportName)) || (v.target.subpath !== undefined && (typeof v.target.subpath !== 'string' || v.target.subpath.length > 200 || (v.target.subpath !== '' && !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(v.target.subpath)) || v.target.subpath.split('/').some(p => p === '..' || p === '.'))) || (v.target.advisoryId !== undefined && (typeof v.target.advisoryId !== 'string' || !/^[A-Za-z0-9_.-]{1,200}$/.test(v.target.advisoryId)))) throw new ScanError('Select a package instance and supply an exported function name (or leave it empty for UNKNOWN).');
}
export function unknownReachability(request: ReachabilityRequest, sources: SourceSnapshot | null, reason: string): ReachabilityReport {
  return { status: 'UNKNOWN', reason, target: request.target, mapping: 'user-declared export; not independently verified',
    coverage: { entrypoints: request.entrypoints, analyzedFiles: [], sourceFilesAvailable: sources?.files.length ?? 0, skippedSources: sources?.skipped ?? [], functionsVisited: 0, callsExamined: 0, completeForDeclaredEntrypoints: false, boundary: 'Captured application source → declared export of the selected locked npm package instance.' },
    evidence: [], gaps: [{ reason }], limitations: LIMITATIONS };
}

export function pythonReachabilityUnknown(request: ReachabilityRequest, sources: SourceSnapshot | null): ReachabilityReport {
  const report = unknownReachability(request, sources, 'Python reachability is UNKNOWN: no Python AST/call analysis is implemented. JavaScript analysis does not apply to Python.');
  report.mapping = 'Python analysis unsupported';
  report.coverage.boundary = 'Python/PyPI dependency inventory only; no Python source call analysis.';
  report.limitations = ['Python reachability is unsupported and remains UNKNOWN. No Python source, imports, build backend, or package scripts are executed.'];
  return report;
}
export function javaReachabilityUnknown(request: ReachabilityRequest, sources: SourceSnapshot | null): ReachabilityReport {
  const report = unknownReachability(request, sources, 'Java reachability is UNKNOWN: no evidence-backed Java call analysis is implemented.');
  report.mapping = 'Java analysis unsupported'; report.coverage.boundary = 'Java/Maven dependency metadata only; no Java call traversal.';
  report.limitations = ['Java reachability is unsupported. Maven, Gradle and uploaded JVM code are never executed.']; return report;
}

type Callable = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction;
type Unit = ts.SourceFile | Callable;
type External = { module: string; exportName: string; namespace: boolean };
const isCallable = (node: ts.Node): node is Callable => ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node);

export function analyzeReachability(sources: SourceSnapshot | null, graph: DependencyGraph, request: ReachabilityRequest): ReachabilityReport {
  const report = unknownReachability(request, sources, 'Analysis is incomplete.'); report.gaps = [];
  const target = graph.nodes.find(n => n.id === request.target.packageNodeId);
  if (target?.ecosystem === 'PyPI') return pythonReachabilityUnknown(request, sources);
  if (target?.ecosystem === 'Maven') return javaReachabilityUnknown(request, sources);
  if (request.entrypoints.some(e => e.file.endsWith('.py'))) return unknownReachability(request, sources, 'Python entrypoints cannot be analyzed by the JavaScript AST engine.');
  if (!target || target.isProject || !target.version) return unknownReachability(request, sources, 'The target must be a locked package instance with a resolved version.');
  if (!request.target.exportName) return unknownReachability(request, sources, 'No affected-function export mapping supplied. Advisory presence does not identify a vulnerable function.');
  if (!sources?.files.length) return unknownReachability(request, sources, 'Source snapshot unavailable. Rescan a repository or ZIP containing source files.');
  const files = new Map(sources.files.filter(f => /\.(?:[cm]?js|jsx|tsx?)$/.test(f.path)).map(f => [`/source/${f.path}`, f.content]));
  const relativeFile = (path: string) => path.slice('/source/'.length);
  const resolveLocal = (specifier: string, containing: string) => {
    const base = posix.normalize(posix.join(posix.dirname(containing), specifier));
    if (!base.startsWith('/source/')) return undefined;
    if (files.has(base)) return base;
    const stem = /\.[cm]?jsx?$/.test(base) ? base.replace(/\.[cm]?jsx?$/, '') : base;
    const candidates = [...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map(ext => stem + ext), ...['index.ts', 'index.tsx', 'index.js', 'index.jsx', 'index.mjs', 'index.cjs'].map(name => `${base}/${name}`)].filter(path => files.has(path));
    return candidates.length === 1 ? candidates[0] : undefined;
  };
  const options: ts.CompilerOptions = { target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, allowJs: true, noLib: true, jsx: ts.JsxEmit.Preserve };
  const host: ts.CompilerHost = {
    getSourceFile: (name, languageVersion) => { const content = files.get(name); return content === undefined ? undefined : ts.createSourceFile(name, content, languageVersion, true); },
    getDefaultLibFileName: () => '/no-lib.d.ts', writeFile: () => {}, getCurrentDirectory: () => '/source', getDirectories: () => [],
    getCanonicalFileName: name => name, useCaseSensitiveFileNames: () => true, getNewLine: () => '\n', fileExists: name => files.has(name), readFile: name => files.get(name),
    resolveModuleNames: (names, containing) => names.map(name => { const resolvedFileName = name.startsWith('.') ? resolveLocal(name, containing) : undefined; return resolvedFileName ? { resolvedFileName } : undefined; }),
  };
  const program = ts.createProgram([...files.keys()], options, host); const checker = program.getTypeChecker();
  const external = new Map<ts.Symbol, External>();
  for (const file of program.getSourceFiles()) for (const statement of file.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.moduleSpecifier.text.startsWith('.') || statement.importClause?.isTypeOnly) continue;
    const module = statement.moduleSpecifier.text; const clause = statement.importClause;
    const add = (name: ts.Identifier, exportName: string, namespace: boolean) => { const symbol = checker.getSymbolAtLocation(name); if (symbol) external.set(symbol, { module, exportName, namespace }); };
    if (clause?.name) add(clause.name, 'default', false);
    const bindings = clause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) add(bindings.name, '*', true);
    else if (bindings) for (const specifier of bindings.elements) if (!specifier.isTypeOnly) add(specifier.name, specifier.propertyName?.text ?? specifier.name.text, false);
  }
  const unalias = (symbol?: ts.Symbol) => { const seen = new Set<ts.Symbol>(); while (symbol && symbol.flags & ts.SymbolFlags.Alias && !seen.has(symbol)) { seen.add(symbol); symbol = checker.getAliasedSymbol(symbol); } return symbol; };
  const callable = (symbol?: ts.Symbol): Callable | undefined => {
    const resolved = unalias(symbol);
    if ((resolved?.declarations?.filter(d => isCallable(d) || ts.isVariableDeclaration(d)).length ?? 0) > 1) return undefined;
    for (const declaration of resolved?.declarations ?? []) {
      if (isCallable(declaration) && declaration.body) return declaration;
      if (ts.isVariableDeclaration(declaration) && declaration.initializer && isCallable(declaration.initializer)) return declaration.initializer;
      if (ts.isExportAssignment(declaration) && isCallable(declaration.expression)) return declaration.expression;
    }
    return undefined;
  };
  const sourceLines = new Map<ts.SourceFile, string[]>();
  const evidence = (node: ts.Node, kind: SourceEvidence['kind'], from: string, to: string): SourceEvidence => {
    const file = node.getSourceFile(); const position = file.getLineAndCharacterOfPosition(node.getStart(file));
    let lines = sourceLines.get(file); if (!lines) { lines = file.text.split('\n'); sourceLines.set(file, lines); }
    return { file: relativeFile(file.fileName), line: position.line + 1, column: position.character + 1, snippet: lines[position.line]?.trim().slice(0, 240) ?? '', kind, from, to };
  };
  const describe = (unit: Unit) => ts.isSourceFile(unit) ? `${relativeFile(unit.fileName)}#<module>` : `${relativeFile(unit.getSourceFile().fileName)}#${unit.name?.getText() ?? (ts.isVariableDeclaration(unit.parent) ? unit.parent.name.getText() : '<anonymous>')}`;
  const gap = (reason: string, node?: ts.Node, from = '') => {
    if (report.gaps.length < 100) report.gaps.push({ reason, ...(node ? { evidence: evidence(node, 'gap', from, reason) } : {}) });
  };
  const queue: { unit: Unit; path: SourceEvidence[] }[] = [];
  for (const entry of request.entrypoints) {
    const file = program.getSourceFile(`/source/${entry.file}`);
    if (!file) { gap(`Entry source not captured: ${entry.file}.`); continue; }
    const entryEvidence = evidence(file, 'entry', '<declared entrypoint>', `${entry.file}#${entry.symbol}`);
    queue.push({ unit: file, path: [entryEvidence] });
    if (entry.symbol !== '<module>') {
      const moduleSymbol = checker.getSymbolAtLocation(file);
      const symbol = moduleSymbol && checker.getExportsOfModule(moduleSymbol).find(s => s.name === entry.symbol);
      const fn = callable(symbol);
      if (fn) queue.push({ unit: fn, path: [evidence(fn, 'entry', '<declared entrypoint>', describe(fn))] });
      else gap(`Entrypoint export is missing or not a supported function: ${entry.file}#${entry.symbol}.`, file);
    }
  }
  const projectDirectories = graph.nodes.filter(n => n.isProject).map(node => ({ node, directory: posix.normalize(posix.join(posix.dirname(node.project), node.installPath)) })).sort((a, b) => b.directory.length - a.directory.length);
  const externalInstance = (specifier: string, file: string) => {
    const parts = specifier.split('/'); const packageName = specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
    const subpath = parts.slice(specifier.startsWith('@') ? 2 : 1).join('/');
    const project = projectDirectories.find(p => p.directory === '.' || file.startsWith(`${p.directory}/`));
    const edges = project ? graph.edges.filter(e => e.from === project.node.id && e.name === packageName) : [];
    const ids = [...new Set(edges.map(e => e.to))];
    return { nodeId: ids.length === 1 ? ids[0] : undefined, subpath };
  };
  let visits = 0; const visited = new Set<Unit>(); const analyzed = new Set<string>(); let foundPath: SourceEvidence[] | undefined;
  const observed: SourceEvidence[] = [];
  for (let i = 0; i < queue.length; i++) {
    const { unit, path } = queue[i]; if (visited.has(unit)) continue;
    if (visited.size >= 1000 || report.coverage.callsExamined >= 5000 || visits >= 100_000) { gap('Traversal resource limit reached.'); break; }
    visited.add(unit); const file = unit.getSourceFile(); analyzed.add(relativeFile(file.fileName)); const from = describe(unit);
    if (ts.isSourceFile(unit)) {
      const diagnostics = program.getSyntacticDiagnostics(unit);
      if (diagnostics.length) { gap('Source has syntax errors; traversal is incomplete.', file, from); continue; }
    } else {
      report.coverage.functionsVisited++;
      if (unit.asteriskToken || ts.getModifiers(unit)?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword)) gap('Async or generator functions are outside coverage.', unit, from);
    }
    const walk = (node: ts.Node): void => {
      if (++visits > 100_000 || report.coverage.callsExamined >= 5000) { if (visits === 100_001 || report.coverage.callsExamined === 5000) gap('Traversal resource limit reached.', node, from); return; }
      if (node !== unit && ts.isFunctionLike(node)) return;
      if (ts.isTypeNode(node)) return;
      if (ts.isClassDeclaration(node) || ts.isClassExpression(node) || ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node)) { gap('Class or JSX/framework dispatch is outside coverage.', node, from); return; }
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        if (ts.isImportDeclaration(node) ? node.importClause?.isTypeOnly : node.isTypeOnly) return;
        const module = node.moduleSpecifier;
        if (module && ts.isStringLiteral(module)) {
          if (module.text.startsWith('.')) {
            const resolved = resolveLocal(module.text, file.fileName); const imported = resolved && program.getSourceFile(resolved);
            if (imported) queue.push({ unit: imported, path: [...path, evidence(node, 'import', from, `${relativeFile(imported.fileName)}#<module>`)] });
            else gap(`Local module is missing, ambiguous, or outside captured source: ${module.text}.`, node, from);
          }
        }
        return;
      }
      if ((ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) || ts.isDeleteExpression(node)) gap('Mutation may change call targets; reassignment is not modeled.', node, from);
      if (ts.isObjectLiteralExpression(node) && node.properties.some(p => ts.isMethodDeclaration(p) || ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p) || ts.isSpreadAssignment(p))) gap('Object methods, accessors, or spread behavior are outside coverage.', node, from);
      if (ts.isAwaitExpression(node) || ts.isYieldExpression(node)) gap('Async scheduling/generator behavior is outside coverage.', node, from);
      if (ts.isNewExpression(node) || ts.isTaggedTemplateExpression(node)) { gap('Constructor or tagged-template dispatch is outside coverage.', node, from); }
      if (ts.isCallExpression(node)) {
        report.coverage.callsExamined++;
        if (node.questionDotToken || (ts.isPropertyAccessExpression(node.expression) && node.expression.questionDotToken)) gap('Optional call behavior is outside coverage.', node, from);
        const call = node.expression;
        const callSymbol = checker.getSymbolAtLocation(call);
        if ((callSymbol?.declarations?.length ?? 0) > 1) gap('Multiple declarations make the call binding ambiguous.', node, from);
        let binding: External | undefined;
        if (ts.isIdentifier(call)) binding = external.get(checker.getSymbolAtLocation(call)!);
        if (ts.isPropertyAccessExpression(call) && ts.isIdentifier(call.expression)) {
          const imported = external.get(checker.getSymbolAtLocation(call.expression)!);
          if (imported?.namespace) binding = { ...imported, exportName: call.name.text, namespace: false };
        }
        const record = evidence(node, 'call', from, call.getText(file).slice(0, 120));
        if (observed.length < 100) observed.push(record);
        if (binding && !binding.namespace) {
          const instance = externalInstance(binding.module, relativeFile(file.fileName));
          if (instance.nodeId === target.id && binding.exportName === request.target.exportName && instance.subpath === (request.target.subpath ?? '')) {
            foundPath ??= [...path, { ...record, kind: 'target', to: `${target.name}@${target.version}:${binding.exportName}` }];
          } else gap('External call internals or package-instance resolution are outside coverage.', node, from);
        } else {
          const symbol = ts.isPropertyAccessExpression(call) ? checker.getSymbolAtLocation(call.name) : checker.getSymbolAtLocation(call);
          const fn = isCallable(call) ? call : callable(symbol);
          if (fn && !node.questionDotToken && !ts.isPropertyAccessExpression(call)) queue.push({ unit: fn, path: [...path, { ...record, to: describe(fn) }] });
          else if (fn && ts.isPropertyAccessExpression(call) && ts.isIdentifier(call.expression) && !external.has(checker.getSymbolAtLocation(call.expression)!)) {
            const namespace = checker.getSymbolAtLocation(call.expression)?.declarations?.some(d => ts.isNamespaceImport(d));
            if (namespace) queue.push({ unit: fn, path: [...path, { ...record, to: describe(fn) }] });
            else gap('Object method dispatch is outside coverage.', node, from);
          } else gap('Dynamic, optional, CommonJS, unresolved, or indirect call is outside coverage.', node, from);
        }
      }
      if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
        const called = ts.isCallExpression(node.parent) && node.parent.expression === node;
        if (!called) gap('Property access may dispatch getters or indirect behavior outside coverage.', node, from);
      }
      if (ts.isIdentifier(node)) {
        const symbol = checker.getSymbolAtLocation(node); const binding = symbol && external.get(symbol);
        if (binding || callable(symbol)) {
          const parent = node.parent;
          const declarationName = (ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent) || ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent)) && parent.name === node;
          const directCall = ts.isCallExpression(parent) && parent.expression === node;
          const namespaceCall = ts.isPropertyAccessExpression(parent) && parent.expression === node && ts.isCallExpression(parent.parent) && parent.parent.expression === parent && binding?.namespace;
          if (!declarationName && !directCall && !namespaceCall && !(ts.isPropertyAccessExpression(parent) && parent.name === node)) gap('Function reference escapes direct-call traversal (alias, callback, return, or property access).', node, from);
        }
      }
      ts.forEachChild(node, walk);
    };
    ts.forEachChild(unit, walk);
  }
  report.coverage.analyzedFiles = [...analyzed].sort();
  report.coverage.completeForDeclaredEntrypoints = report.gaps.length === 0;
  report.status = report.gaps.length ? 'UNKNOWN' : foundPath ? 'REACHABLE' : 'NOT REACHABLE';
  report.reason = report.gaps.length ? 'Unsupported behavior or missing evidence prevents a conclusive scoped result.' : foundPath ? 'A syntactic call path reaches the user-declared affected export of the selected locked package instance.' : 'No call to the declared affected export was found within the declared entrypoint closure and supported static model.';
  report.evidence = (foundPath ?? observed).slice(0, 100);
  if (!report.evidence.length) report.evidence = queue.slice(0, 10).flatMap(item => item.path.slice(0, 1));
  return report;
}
