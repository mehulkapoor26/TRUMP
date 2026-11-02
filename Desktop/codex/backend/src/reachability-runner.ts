import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { DependencyGraph, ReachabilityReport, ReachabilityRequest, SourceSnapshot } from '@traceguard/shared';
import { unknownReachability, pythonReachabilityUnknown, javaReachabilityUnknown } from './reachability.js';

export function runReachability(sources: SourceSnapshot | null, graph: DependencyGraph, request: ReachabilityRequest): Promise<ReachabilityReport> {
  if (graph.nodes.find(n => n.id === request.target.packageNodeId)?.ecosystem === 'PyPI') return Promise.resolve(pythonReachabilityUnknown(request, sources));
  if (graph.nodes.find(n => n.id === request.target.packageNodeId)?.ecosystem === 'Maven') return Promise.resolve(javaReachabilityUnknown(request, sources));
  return new Promise(resolve => {
    const development = import.meta.url.endsWith('.ts');
    const file = fileURLToPath(new URL(development ? './reachability-worker.ts' : './reachability-worker.js', import.meta.url));
    const child = fork(file, [], { execArgv: ['--max-old-space-size=192', ...(development ? ['--import', 'tsx'] : [])], stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    let settled = false;
    const finish = (report: ReachabilityReport) => { if (settled) return; settled = true; clearTimeout(timer); child.kill('SIGKILL'); resolve(report); };
    const timer = setTimeout(() => finish(unknownReachability(request, sources, 'Static analysis exceeded the six-second time limit.')), 6000);
    child.on('message', message => finish(message as ReachabilityReport));
    child.on('error', () => finish(unknownReachability(request, sources, 'Static analysis worker could not start.')));
    child.on('exit', () => finish(unknownReachability(request, sources, 'Static analysis worker stopped before producing a result (resource limit or unsupported input).')));
    child.send({ sources, graph, request }, error => { if (error) finish(unknownReachability(request, sources, 'Static analysis input could not be delivered.')); });
  });
}
