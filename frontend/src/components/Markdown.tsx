import React from 'react';

// Renders the small markdown subset LSADRA narratives use: headings (#, ##, ###),
// paragraphs, "-"/"*" and "1." lists, **bold**, *italic* / _italic_, `code`
// and backslash escapes.
//
// It builds React elements only. There is no HTML passthrough and no links,
// so text that came from logs can never become markup or a clickable URL.
// The backend already escapes log-derived values (lsadra/explainability/
// sanitize.py); this renderer honours those escapes so "\*" shows as "*".

type Inline = React.ReactNode[];

const ESCAPABLE = new Set('\\`*_[]<>~|$#+-.!(){}'.split(''));

function renderInline(text: string, keyBase: string): Inline {
  const out: Inline = [];
  let buf = '';
  let i = 0;
  let k = 0;
  const flush = () => { if (buf) { out.push(buf); buf = ''; } };

  // Find the closing marker, skipping escaped characters.
  const findClose = (marker: string, from: number) => {
    for (let j = from; j < text.length; j++) {
      if (text[j] === '\\') { j++; continue; }
      if (text.startsWith(marker, j)) return j;
    }
    return -1;
  };

  while (i < text.length) {
    const ch = text[i];
    if (ch === '\\' && i + 1 < text.length && ESCAPABLE.has(text[i + 1])) {
      buf += text[i + 1];
      i += 2;
      continue;
    }
    if (ch === '`') {
      const end = text.indexOf('`', i + 1);
      if (end > i + 1) {
        flush();
        out.push(<code key={`${keyBase}-${k++}`} className="px-1 rounded bg-[rgba(255,255,255,0.08)] text-[var(--color-text)]">{text.slice(i + 1, end)}</code>);
        i = end + 1;
        continue;
      }
    }
    if (text.startsWith('**', i)) {
      const end = findClose('**', i + 2);
      if (end > i + 2) {
        flush();
        out.push(<strong key={`${keyBase}-${k++}`} className="font-bold text-white">{renderInline(text.slice(i + 2, end), `${keyBase}-${k}`)}</strong>);
        i = end + 2;
        continue;
      }
    }
    if ((ch === '*' || ch === '_') && text[i + 1] !== ch && text[i + 1] !== ' ') {
      const end = findClose(ch, i + 1);
      if (end > i + 1 && text[end - 1] !== ' ') {
        flush();
        out.push(<em key={`${keyBase}-${k++}`}>{renderInline(text.slice(i + 1, end), `${keyBase}-${k}`)}</em>);
        i = end + 1;
        continue;
      }
    }
    buf += ch;
    i++;
  }
  flush();
  return out;
}

type Block =
  | { kind: 'h'; level: number; text: string }
  | { kind: 'p'; text: string }
  | { kind: 'ul' | 'ol'; items: string[] };

function parseBlocks(src: string): Block[] {
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: { kind: 'ul' | 'ol'; items: string[] } | null = null;
  const endPara = () => { if (para.length) { blocks.push({ kind: 'p', text: para.join(' ') }); para = []; } };
  const endList = () => { if (list) { blocks.push(list); list = null; } };

  for (const raw of src.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.trim();
    if (!line) { endPara(); endList(); continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) { endPara(); endList(); blocks.push({ kind: 'h', level: h[1].length, text: h[2] }); continue; }
    const ul = /^[-*]\s+(.*)$/.exec(line);
    const ol = /^\d+[.)]\s+(.*)$/.exec(line);
    if (ul || ol) {
      endPara();
      const kind = ul ? 'ul' : 'ol';
      if (!list || list.kind !== kind) { endList(); list = { kind, items: [] }; }
      list.items.push((ul || ol)![1]);
      continue;
    }
    endList();
    para.push(line);
  }
  endPara();
  endList();
  return blocks;
}

const HEADING_CLASS = ['', 'text-base', 'text-sm', 'text-sm'];

const Markdown: React.FC<{ text?: string | null; className?: string }> = ({ text, className }) => {
  if (!text) return null;
  const blocks = parseBlocks(text);
  return (
    <div className={`space-y-2 leading-relaxed ${className || ''}`}>
      {blocks.map((b, i) => {
        if (b.kind === 'h') {
          const Tag = (`h${Math.min(b.level + 2, 6)}`) as 'h3' | 'h4' | 'h5';
          return <Tag key={i} className={`${HEADING_CLASS[b.level]} font-display font-bold text-white mt-2`}>{renderInline(b.text, `h${i}`)}</Tag>;
        }
        if (b.kind === 'p') return <p key={i}>{renderInline(b.text, `p${i}`)}</p>;
        const List = b.kind;
        return (
          <List key={i} className={`${b.kind === 'ul' ? 'list-disc' : 'list-decimal'} pl-5 space-y-1`}>
            {b.items.map((it, j) => <li key={j}>{renderInline(it, `l${i}-${j}`)}</li>)}
          </List>
        );
      })}
    </div>
  );
};

export default Markdown;
