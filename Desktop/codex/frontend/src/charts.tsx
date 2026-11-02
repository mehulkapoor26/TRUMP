import type { DependencyGraph, VulnerabilityReport } from '@traceguard/shared';
import { Panel } from './ui';

export function AdvisoryChart({ graph, report }: { graph: DependencyGraph; report?: VulnerabilityReport }) {
  const packages = graph.nodes.filter(n => !n.isProject);
  const checks = new Map(report?.checks.map(c => [c.nodeId, c]) ?? []);
  const values = [
    { name: 'Advisory match', color: '#fb7185', count: packages.filter(n => checks.get(n.id)?.status === 'matched').length },
    { name: 'No known match', color: '#b4f477', count: packages.filter(n => checks.get(n.id)?.status === 'no-known').length },
    { name: 'Unknown / unchecked', color: '#43536b', count: packages.filter(n => !checks.has(n.id) || checks.get(n.id)?.status === 'unknown').length },
  ];
  let offset = 0;
  return <Panel title="Advisory coverage" subtitle={report ? 'Package instances · latest OSV check' : 'Package instances · check not run'}><div className="donut-layout"><div className="donut"><svg viewBox="0 0 160 160" role="img" aria-label={values.map(v => `${v.name}: ${v.count}`).join(', ')}><circle cx="80" cy="80" r="62" fill="none" stroke="#1d2939" strokeWidth="15" />{values.map(v => { const length = packages.length ? v.count / packages.length * 100 : 0; const start = offset; offset += length; return <circle key={v.name} cx="80" cy="80" r="62" fill="none" stroke={v.color} strokeWidth="15" pathLength="100" strokeDasharray={`${length} ${100 - length}`} strokeDashoffset={-start} transform="rotate(-90 80 80)" />; })}</svg><div className="donut-number"><strong>{packages.length}</strong><span>packages</span></div></div><ul className="chart-legend">{values.map(v => <li key={v.name}><span style={{ background: v.color }} /><p>{v.name}</p><strong>{v.count}</strong></li>)}</ul></div><p className="chart-footnote">No known match is not a safety guarantee. Unknown packages have not been cleared.</p></Panel>;
}
export function RelationshipChart({ graph }: { graph: DependencyGraph }) {
  const values = [{ kind: 'runtime', color: '#7de4d6' }, { kind: 'dev', color: '#9a9af5' }, { kind: 'optional', color: '#e5bc70' }, { kind: 'peer', color: '#6d9ee6' }].map(v => ({ ...v, count: graph.edges.filter(e => e.kind === v.kind).length }));
  const max = Math.max(1, ...values.map(v => v.count));
  return <Panel title="Dependency relationships" subtitle="Declared edge types across the locked graph"><div className="bar-chart" role="img" aria-label={values.map(v => `${v.kind}: ${v.count}`).join(', ')}>{values.map(v => <div className="bar-row" key={v.kind}><span>{v.kind}</span><div className="bar-track"><i style={{ width: `${v.count / max * 100}%`, background: v.color }} /></div><strong>{v.count}</strong></div>)}</div><p className="chart-footnote">Counts describe package relationships, not vulnerable function calls.</p></Panel>;
}
