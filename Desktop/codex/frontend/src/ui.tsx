import type { ReactNode } from 'react';
import { ArrowUpRight, ChevronRight, ShieldCheck } from 'lucide-react';

export function Brand({ compact = false }: { compact?: boolean }) {
  return <a className="brand" href="#/" aria-label="TRACEGUARD home"><span className="brand-mark"><ShieldCheck size={22} strokeWidth={1.7} /></span>{!compact && <span>TRACE<span className="brand-light">GUARD</span><small>SOFTWARE SUPPLY CHAIN SECURITY</small></span>}</a>;
}
export function Badge({ children, tone = 'muted' }: { children: ReactNode; tone?: 'muted' | 'green' | 'red' | 'amber' | 'purple' }) { return <span className={`badge badge-${tone}`}><i />{children}</span>; }
export function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div><div className="heading-actions">{action}</div></div>;
}
export function EmptyState({ icon, title, children, action }: { icon: ReactNode; title: string; children: ReactNode; action?: ReactNode }) { return <div className="empty-state"><span className="empty-icon">{icon}</span><h2>{title}</h2><p>{children}</p>{action}</div>; }
export function Metric({ label, value, detail, icon, tone = 'green' }: { label: string; value: ReactNode; detail: string; icon: ReactNode; tone?: string }) { return <article className={`metric metric-${tone}`}><div className="metric-label">{label}<span>{icon}</span></div><strong>{value}</strong><p>{detail}</p></article>; }
export function Panel({ title, subtitle, action, children, className = '' }: { title: string; subtitle?: string; action?: ReactNode; children: ReactNode; className?: string }) { return <section className={`surface ${className}`}><header className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</header>{children}</section>; }
export function TextLink({ href, children }: { href: string; children: ReactNode }) { return <a className="text-link" href={href}>{children}<ChevronRight size={15} /></a>; }
export function ActionLink({ href, children, secondary = false }: { href: string; children: ReactNode; secondary?: boolean }) { return <a className={secondary ? 'button button-secondary' : 'button'} href={href}>{children}<ArrowUpRight size={17} /></a>; }
export const formatDate = (date: string) => new Date(date).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
export const sourceName = (source: string) => source.startsWith('https://github.com/') ? source.replace('https://github.com/', '') : source;
