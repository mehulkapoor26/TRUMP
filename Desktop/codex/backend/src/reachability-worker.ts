import { analyzeReachability, unknownReachability } from './reachability.js';
import type { DependencyGraph, ReachabilityRequest, SourceSnapshot } from '@traceguard/shared';
process.once('message', (message: { sources: SourceSnapshot | null; graph: DependencyGraph; request: ReachabilityRequest }) => {
  let result;
  try { result = analyzeReachability(message.sources, message.graph, message.request); }
  catch { result = unknownReachability(message.request, message.sources, 'Parser or traversal could not analyze this source safely.'); }
  process.send?.(result);
});
