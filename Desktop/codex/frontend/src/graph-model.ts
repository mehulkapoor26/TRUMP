import type { DependencyGraph } from '@traceguard/shared';

export function graphIndex(graph: DependencyGraph) {
  const nodes = new Map(graph.nodes.map(n => [n.id, n]));
  const parents = new Map<string, string[]>(); const children = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (!nodes.has(edge.from) || !nodes.has(edge.to)) continue;
    const p = parents.get(edge.to) ?? []; p.push(edge.from); parents.set(edge.to, p);
    const c = children.get(edge.from) ?? []; c.push(edge.to); children.set(edge.from, c);
  }
  return { nodes, parents, children };
}

export function dependencyImpact(graph: DependencyGraph, selected: string) {
  const index = graphIndex(graph);
  const ancestors = new Set<string>(); const next = new Map<string, string>();
  const queue = [selected]; const seen = new Set([selected]);
  for (let i = 0; i < queue.length; i++) {
    for (const parent of index.parents.get(queue[i]) ?? []) {
      if (seen.has(parent)) continue;
      seen.add(parent); ancestors.add(parent); next.set(parent, queue[i]); queue.push(parent);
    }
  }
  const roots = graph.roots.filter(id => ancestors.has(id) || id === selected);
  const paths = roots.slice(0, 5).map(root => {
    const path = [root];
    while (path.at(-1) !== selected && path.length < 100) {
      const child = next.get(path.at(-1)!); if (!child) break; path.push(child);
    }
    return { ids: path, truncated: path.at(-1) !== selected };
  });
  return { ancestors, roots, paths, pathsLimited: roots.length > 5 };
}

export function graphLayout(graph: DependencyGraph, selected?: string, limit = 300) {
  const index = graphIndex(graph);
  const depths = new Map<string, number>(); const queue = graph.roots.filter(id => index.nodes.has(id));
  queue.forEach(id => depths.set(id, 0));
  for (let i = 0; i < queue.length; i++) {
    for (const child of index.children.get(queue[i]) ?? []) {
      if (!depths.has(child)) { depths.set(child, depths.get(queue[i])! + 1); queue.push(child); }
    }
  }
  const ordered = [...queue, ...graph.nodes.filter(n => !depths.has(n.id)).map(n => n.id)];
  const required = selected && index.nodes.has(selected) ? [selected, ...dependencyImpact(graph, selected).paths.flatMap(p => p.ids).reverse(), ...(index.parents.get(selected) ?? []), ...(index.children.get(selected) ?? [])] : [];
  const visible = [...new Set([...required, ...ordered])].slice(0, limit);
  const visibleIds = new Set(visible); const rows = new Map<number, number>();
  const orphanDepth = Math.max(0, ...depths.values()) + 1;
  return {
    nodes: visible.map(id => {
      const depth = depths.get(id) ?? orphanDepth; const row = rows.get(depth) ?? 0; rows.set(depth, row + 1);
      return { node: index.nodes.get(id)!, position: { x: depth * 300, y: row * 150 } };
    }),
    edges: graph.edges.filter(edge => visibleIds.has(edge.from) && visibleIds.has(edge.to)),
    omitted: graph.nodes.length - visible.length,
  };
}
