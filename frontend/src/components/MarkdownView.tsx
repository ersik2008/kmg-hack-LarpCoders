import React, { useMemo } from 'react';

/**
 * Отрисовка Markdown, который возвращает AI-агент.
 *
 * Заключение приходит размеченным (## заголовки, списки, **жирный**, `код`,
 * цитаты), и раньше оно выводилось как обычный текст — разметка читалась
 * сырыми символами. Полноценный парсер здесь не нужен: поддерживается ровно
 * тот набор, который модель реально использует.
 */

/** Инлайновая разметка: **жирный**, *курсив*, `код`. */
const renderInline = (text: string): React.ReactNode[] => {
  const parts: React.ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }

    const token = match[0];
    if (token.startsWith('**')) {
      parts.push(
        <strong key={key++} style={{ color: '#f8fafc', fontWeight: 650 }}>
          {token.slice(2, -2)}
        </strong>,
      );
    } else if (token.startsWith('`')) {
      parts.push(
        <code
          key={key++}
          style={{
            background: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid rgba(56, 189, 248, 0.2)',
            borderRadius: '4px',
            padding: '0.1rem 0.35rem',
            fontSize: '0.82em',
            color: '#7dd3fc',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
            wordBreak: 'break-all',
          }}
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      parts.push(
        <em key={key++} style={{ color: '#cbd5e1' }}>
          {token.slice(1, -1)}
        </em>,
      );
    }

    lastIndex = match.index + token.length;
  }

  if (lastIndex < text.length) parts.push(text.slice(lastIndex));
  return parts;
};

interface Block {
  kind: 'heading' | 'list' | 'quote' | 'code' | 'paragraph';
  level?: number;
  ordered?: boolean;
  lines: string[];
}

/** Разбор построчно: блоки разделяются сменой типа строки. */
const parseBlocks = (markdown: string): Block[] => {
  const blocks: Block[] = [];
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');

  let current: Block | null = null;
  const flush = () => {
    if (current && current.lines.length > 0) blocks.push(current);
    current = null;
  };

  let inCodeFence = false;

  for (const raw of lines) {
    const line = raw.trimEnd();

    if (line.trim().startsWith('```')) {
      if (inCodeFence) {
        flush();
        inCodeFence = false;
      } else {
        flush();
        inCodeFence = true;
        current = { kind: 'code', lines: [] };
      }
      continue;
    }

    if (inCodeFence) {
      if (current) current.lines.push(raw);
      continue;
    }

    if (!line.trim()) {
      flush();
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      flush();
      blocks.push({ kind: 'heading', level: heading[1].length, lines: [heading[2]] });
      continue;
    }

    if (line.startsWith('>')) {
      if (current?.kind !== 'quote') {
        flush();
        current = { kind: 'quote', lines: [] };
      }
      current.lines.push(line.replace(/^>\s?/, ''));
      continue;
    }

    const bullet = line.match(/^\s*[-*+]\s+(.*)$/);
    const numbered = line.match(/^\s*(\d+)[.)]\s+(.*)$/);

    if (bullet || numbered) {
      const ordered = Boolean(numbered);
      if (current?.kind !== 'list' || current.ordered !== ordered) {
        flush();
        current = { kind: 'list', ordered, lines: [] };
      }
      current.lines.push(bullet ? bullet[1] : numbered![2]);
      continue;
    }

    if (current?.kind !== 'paragraph') {
      flush();
      current = { kind: 'paragraph', lines: [] };
    }
    current.lines.push(line);
  }

  flush();
  return blocks;
};

const MarkdownView = ({ children }: { children: string }) => {
  const blocks = useMemo(() => parseBlocks(children || ''), [children]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.87rem', lineHeight: 1.65 }}>
      {blocks.map((block, index) => {
        if (block.kind === 'heading') {
          const size = block.level === 1 ? '1.15rem' : block.level === 2 ? '1rem' : '0.9rem';
          return (
            <h4
              key={index}
              style={{
                margin: index === 0 ? 0 : '0.35rem 0 0',
                fontSize: size,
                color: '#f8fafc',
                fontWeight: 650,
                letterSpacing: '-0.01em',
              }}
            >
              {renderInline(block.lines[0])}
            </h4>
          );
        }

        if (block.kind === 'quote') {
          return (
            <div
              key={index}
              style={{
                borderLeft: '3px solid var(--primary)',
                background: 'rgba(99, 102, 241, 0.07)',
                borderRadius: '0 6px 6px 0',
                padding: '0.6rem 0.9rem',
                color: '#cbd5e1',
                fontSize: '0.84rem',
              }}
            >
              {block.lines.map((line, i) => (
                <div key={i}>{renderInline(line)}</div>
              ))}
            </div>
          );
        }

        if (block.kind === 'code') {
          return (
            <pre
              key={index}
              style={{
                margin: 0,
                background: '#040711',
                border: '1px solid #1e293b',
                borderRadius: '6px',
                padding: '0.75rem 1rem',
                overflowX: 'auto',
                fontSize: '0.78rem',
                color: '#7dd3fc',
                lineHeight: 1.5,
              }}
            >
              {block.lines.join('\n')}
            </pre>
          );
        }

        if (block.kind === 'list') {
          const Tag = block.ordered ? 'ol' : 'ul';
          return (
            <Tag
              key={index}
              style={{
                margin: 0,
                paddingLeft: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
                color: '#cbd5e1',
              }}
            >
              {block.lines.map((line, i) => (
                <li key={i} style={{ paddingLeft: '0.15rem' }}>
                  {renderInline(line)}
                </li>
              ))}
            </Tag>
          );
        }

        return (
          <p key={index} style={{ margin: 0, color: '#cbd5e1' }}>
            {renderInline(block.lines.join(' '))}
          </p>
        );
      })}
    </div>
  );
};

export default MarkdownView;
