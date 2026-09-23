/**
 * The small slice of Markdown the assistant actually writes: headings, bold, inline code, lists,
 * tables and rules.
 *
 * It builds React elements rather than setting innerHTML. That is the whole reason it exists: the
 * text comes from a language model and can quote whatever the operator typed, so handing it to a
 * HTML parser would make every answer a script-injection surface. Nothing here can produce a node
 * that React did not create, so there is nothing to sanitise.
 *
 * Anything it does not recognise stays as written -unknown syntax must read as plain text, never
 * disappear.
 */

// `code`, **bold**, *italic* -longest delimiter first so ** is not eaten by *
const INLINE = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g;

function inline(text, keyPrefix = 'i') {
  // a model writing a table sometimes ends a cell with a literal <br>
  const pieces = String(text).split(/<br\s*\/?>/i);
  return pieces.flatMap((piece, p) => {
    const nodes = piece.split(INLINE).filter(Boolean).map((token, i) => {
      const key = `${keyPrefix}-${p}-${i}`;
      if (token.startsWith('`') && token.endsWith('`') && token.length > 1) {
        return <code key={key} className="md-code">{token.slice(1, -1)}</code>;
      }
      if (token.startsWith('**') && token.endsWith('**') && token.length > 3) {
        return <strong key={key}>{token.slice(2, -2)}</strong>;
      }
      if (token.startsWith('*') && token.endsWith('*') && token.length > 2) {
        return <em key={key}>{token.slice(1, -1)}</em>;
      }
      return token;
    });
    return p < pieces.length - 1 ? [...nodes, <br key={`${keyPrefix}-br-${p}`} />] : nodes;
  });
}

const cells = (row) => row.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
const isDivider = (line) => /^\|?[\s:|-]*-[\s:|-]*\|?$/.test(line) && line.includes('-');
const isRule = (line) => /^\s*([-*_])\1{2,}\s*$/.test(line);
const bullet = (line) => line.match(/^\s*[-*•]\s+(.*)$/);
const numbered = (line) => line.match(/^\s*\d+[.)]\s+(.*)$/);
const heading = (line) => line.match(/^(#{1,6})\s+(.*)$/);

export function parseBlocks(text) {
  const lines = String(text ?? '').replace(/\r\n/g, '\n').split('\n');
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (!line.trim()) { i += 1; continue; }

    if (isRule(line)) { blocks.push({ type: 'rule' }); i += 1; continue; }

    const head = heading(line);
    if (head) {
      blocks.push({ type: 'heading', level: Math.min(head[1].length + 2, 6), text: head[2] });
      i += 1;
      continue;
    }

    // a table needs its divider row, otherwise a line of pipes is just a line
    if (line.trim().startsWith('|') && isDivider(lines[i + 1] || '')) {
      const header = cells(line.trim());
      const rows = [];
      i += 2;
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(cells(lines[i].trim()));
        i += 1;
      }
      blocks.push({ type: 'table', header, rows });
      continue;
    }

    if (bullet(line) || numbered(line)) {
      const ordered = !bullet(line);
      const items = [];
      while (i < lines.length) {
        const match = ordered ? numbered(lines[i]) : bullet(lines[i]);
        if (!match) break;
        items.push(match[1]);
        i += 1;
      }
      blocks.push({ type: 'list', ordered, items });
      continue;
    }

    // Only a real table interrupts a paragraph. A stray line of pipes is text, and dropping it
    // would lose content -the one thing this renderer must never do.
    const startsTable = (n) => lines[n].trim().startsWith('|') && isDivider(lines[n + 1] || '');
    const paragraph = [];
    while (i < lines.length && lines[i].trim() && !isRule(lines[i]) && !heading(lines[i])
           && !bullet(lines[i]) && !numbered(lines[i]) && !startsTable(i)) {
      paragraph.push(lines[i].trim());
      i += 1;
    }
    if (paragraph.length) blocks.push({ type: 'paragraph', text: paragraph.join(' ') });
    else i += 1;                       // a line no rule claimed: never loop on it
  }
  return blocks;
}

export default function Markdown({ text, className = 'md' }) {
  const blocks = parseBlocks(text);
  return (
    <div className={className}>
      {blocks.map((block, b) => {
        if (block.type === 'rule') return <hr key={b} className="md-rule" />;
        if (block.type === 'heading') {
          const Tag = `h${block.level}`;
          return <Tag key={b} className="md-h">{inline(block.text, `h${b}`)}</Tag>;
        }
        if (block.type === 'list') {
          const Tag = block.ordered ? 'ol' : 'ul';
          return (
            <Tag key={b} className="md-list">
              {block.items.map((item, n) => <li key={n}>{inline(item, `l${b}-${n}`)}</li>)}
            </Tag>
          );
        }
        if (block.type === 'table') {
          return (
            <div key={b} className="md-table-wrap">
              <table className="md-table">
                <thead>
                  <tr>{block.header.map((c, n) => <th key={n}>{inline(c, `th${b}-${n}`)}</th>)}</tr>
                </thead>
                <tbody>
                  {block.rows.map((row, r) => (
                    <tr key={r}>{row.map((c, n) => <td key={n}>{inline(c, `td${b}-${r}-${n}`)}</td>)}</tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }
        return <p key={b} className="md-p">{inline(block.text, `p${b}`)}</p>;
      })}
    </div>
  );
}
