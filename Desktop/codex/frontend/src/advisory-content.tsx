import type { ReactNode } from 'react';

export function safeHref(value: string): string | undefined {
  try { const url = new URL(value); return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined; }
  catch { return undefined; }
}

function inline(text: string, keyPrefix: string): ReactNode[] {
  const parts: ReactNode[] = [];
  const pattern = /(!?)\[([^\]]+)\]\(([^\s)]+)(?:\s+"[^"]*")?\)|`([^`]+)`|\*\*([^*]+)\*\*|__([^_]+)__|\*([^*]+)\*/g;
  let cursor = 0; let index = 0; let match: RegExpExecArray | null;
  while ((match = pattern.exec(text))) {
    if (match.index > cursor) parts.push(text.slice(cursor, match.index));
    const key = `${keyPrefix}-${index++}`;
    if (match[2] !== undefined) {
      const href = safeHref(match[3]);
      if (match[1] === '!') parts.push(match[2]);
      else if (href) parts.push(<a key={key} href={href} target="_blank" rel="noreferrer noopener">{match[2]}</a>);
      else parts.push(match[2]);
    } else if (match[4] !== undefined) parts.push(<code key={key}>{match[4]}</code>);
    else if (match[5] !== undefined || match[6] !== undefined) parts.push(<strong key={key}>{match[5] ?? match[6]}</strong>);
    else if (match[7] !== undefined) parts.push(<em key={key}>{match[7]}</em>);
    cursor = pattern.lastIndex;
  }
  if (cursor < text.length) parts.push(text.slice(cursor));
  return parts;
}

/** Renders a conservative Markdown subset as React text nodes; raw HTML is never interpreted. */
export function AdvisoryMarkdown({ source }: { source: string }) {
  const lines = source.replace(/\r\n?/g, '\n').split('\n');
  const blocks: ReactNode[] = []; let paragraph: string[] = []; let list: string[] = [];
  const flushParagraph = () => { if (paragraph.length) { blocks.push(<p key={`p-${blocks.length}`}>{inline(paragraph.join(' '), `p-${blocks.length}`)}</p>); paragraph = []; } };
  const flushList = () => { if (list.length) { blocks.push(<ul key={`ul-${blocks.length}`}>{list.map((item, i) => <li key={i}>{inline(item, `li-${blocks.length}-${i}`)}</li>)}</ul>); list = []; } };
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { flushParagraph(); flushList(); continue; }
    const heading = /^(#{1,6})\s+(.+)$/.exec(trimmed);
    if (heading) { flushParagraph(); flushList(); blocks.push(<h4 key={`h-${blocks.length}`}>{inline(heading[2], `h-${blocks.length}`)}</h4>); continue; }
    const item = /^(?:[-*+]\s+|\d+[.)]\s+)(.+)$/.exec(trimmed);
    if (item) { flushParagraph(); list.push(item[1]); continue; }
    if (/^<\/?[a-z][^>]*>$/i.test(trimmed)) continue;
    flushList(); paragraph.push(trimmed.replace(/^>\s?/, ''));
  }
  flushParagraph(); flushList();
  return <div className="advisory-markdown">{blocks}</div>;
}

export function advisorySentences(source: string, count: number, maxLength = 420, start = 0): string {
  const plain = source.replace(/<[^>]*>/g, ' ').replace(/!?(\[([^\]]+)\]\([^)]*\))/g, '$2').replace(/[`*_#>~]/g, '').replace(/\s+/g, ' ').trim();
  if (!plain) return '';
  const protectedDecimals = plain.replace(/(?<=\d)\.(?=\d)/g, '\u0000');
  const sentences = protectedDecimals.match(/[^.!?]+(?:[.!?]+|$)/g) ?? [protectedDecimals];
  let result = sentences.slice(start, start + count).join(' ').replace(/\u0000/g, '.').replace(/\s+/g, ' ').trim();
  if (result.length > maxLength) result = `${result.slice(0, maxLength - 1).trimEnd()}…`;
  return result;
}

export function advisoryImpact(description: string, summary: string): string {
  const plain = description.replace(/<[^>]*>/g, ' ').replace(/!?\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[`*_#>~]/g, '').replace(/\s+/g, ' ').trim();
  const protectedText = plain.replace(/(?<=\d)\.(?=\d)/g, '\u0000');
  const sentences = (protectedText.match(/[^.!?]+(?:[.!?]+|$)/g) ?? [protectedText]).map(value => value.replace(/\u0000/g, '.').trim());
  const candidates = sentences.filter(sentence => /\b(?:attacker|attackers|allow|allows|allowing|can|could|cause|causes|causing|execute|execution|denial.of.service|prototype pollution|command injection|arbitrary|remote|bypass|read|write|expose|crash|privilege|compromise|impact|vulnerable|vulnerability)\b/i.test(sentence) && !/\b(?:steps to reproduce|proof of concept|poc|reproduction|reporter|credit|references?)\b/i.test(sentence));
  const result = candidates.slice(0, 2).join(' ').slice(0, 520).trim();
  return result || `The advisory describes ${advisorySentences(summary, 1, 240) || 'a risk in this dependency'}. Whether the affected behavior can be triggered depends on the application's use and the conditions in the full advisory.`;
}
