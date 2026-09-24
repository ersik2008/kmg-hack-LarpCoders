import { useEffect, useState } from 'react';

/**
 * Матрица функций информационной безопасности.
 *
 * Отвечает на вопрос, отличный от таблицы находок: не «где уязвимость», а
 * «реализован ли в проекте сам контроль безопасности». Репозиторий без
 * авторизации не даст ни одной находки сканера, но контроль при этом
 * отсутствует полностью.
 */

const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  IMPLEMENTED: { label: 'Реализован', color: '#4ade80', bg: 'rgba(34, 197, 94, 0.12)' },
  PARTIAL: { label: 'Частично', color: '#fcd34d', bg: 'rgba(245, 158, 11, 0.12)' },
  MISSING: { label: 'Отсутствует', color: '#f87171', bg: 'rgba(239, 68, 68, 0.12)' },
  NOT_APPLICABLE: { label: 'Неприменимо', color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.10)' },
  UNKNOWN: { label: 'Не определён', color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.10)' },
};

interface ControlEvidence {
  filePath: string;
  line: number;
  snippet: string;
  note: string;
}

interface ControlRow {
  id: string;
  control: string;
  title: string;
  status: string;
  confidence: string;
  summary: string;
  risk: string | null;
  recommendation: string | null;
  evidence: ControlEvidence[] | null;
}

interface ControlsResponse {
  controls: ControlRow[];
  summary: {
    total: number;
    implemented: number;
    partial: number;
    missing: number;
    notApplicable: number;
    unknown: number;
    coverage: number | null;
  };
}

const SecurityControlsPanel = ({
  scanId,
  scanStatus,
  onOpenFile,
}: {
  scanId?: string;
  scanStatus?: string;
  /** Открывает файл в редакторе страницы: подтверждение должно вести к коду. */
  onOpenFile?: (filePath: string, line?: number) => void;
}) => {
  const [data, setData] = useState<ControlsResponse | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;

    const load = async () => {
      try {
        const token = localStorage.getItem('kmg_token');
        const res = await fetch(`http://localhost:3000/api/scans/${scanId}/controls`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        if (!cancelled) setData(await res.json());
      } catch {
        if (!cancelled) setData(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [scanId, scanStatus]);

  if (loading) return null;

  const controls = data?.controls || [];
  // Контроли оцениваются на этапе AI-анализа: пока их нет — честнее не
  // показывать ничего, чем показывать пустую матрицу.
  if (controls.length === 0) return null;

  const summary = data!.summary;

  const chips: Array<[string, number]> = [
    ['IMPLEMENTED', summary.implemented],
    ['PARTIAL', summary.partial],
    ['MISSING', summary.missing],
    ['NOT_APPLICABLE', summary.notApplicable],
    ['UNKNOWN', summary.unknown],
  ];

  return (
    <div className="card" style={{ padding: 0 }}>
      <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.05rem' }}>Функции информационной безопасности</h3>
            <p style={{ margin: '0.25rem 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Реализован ли каждый контроль в проекте — с подтверждением из кода
            </p>
          </div>

          {summary.coverage != null && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Покрытие контролей</div>
              <div
                style={{
                  fontSize: '1.5rem',
                  fontWeight: 700,
                  color:
                    summary.coverage >= 70
                      ? 'var(--accent)'
                      : summary.coverage >= 40
                        ? 'var(--warning)'
                        : 'var(--danger)',
                }}
              >
                {summary.coverage}%
              </div>
            </div>
          )}
        </div>

        {/* Полоса покрытия: доля реализованных контролей читается с одного взгляда. */}
        {summary.coverage != null && (
          <div style={{ marginTop: '0.85rem', height: '6px', borderRadius: '999px', background: 'var(--bg-dark)', overflow: 'hidden', display: 'flex' }}>
            <div
              style={{
                width: `${summary.total ? (summary.implemented / summary.total) * 100 : 0}%`,
                background: '#22c55e',
              }}
            />
            <div
              style={{
                width: `${summary.total ? (summary.partial / summary.total) * 100 : 0}%`,
                background: '#f59e0b',
              }}
            />
            <div
              style={{
                width: `${summary.total ? (summary.missing / summary.total) * 100 : 0}%`,
                background: '#ef4444',
              }}
            />
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.9rem', flexWrap: 'wrap' }}>
          {chips.map(([status, count]) => {
            if (!count) return null;
            const meta = STATUS_META[status];
            return (
              <span
                key={status}
                style={{
                  fontSize: '0.75rem',
                  padding: '0.25rem 0.6rem',
                  borderRadius: '999px',
                  background: meta.bg,
                  color: meta.color,
                  border: `1px solid ${meta.color}33`,
                }}
              >
                {meta.label}: {count}
              </span>
            );
          })}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {controls.map(control => {
          const meta = STATUS_META[control.status] || STATUS_META.UNKNOWN;
          const isOpen = expanded === control.id;
          const evidence = control.evidence || [];

          return (
            <div key={control.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
              <button
                onClick={() => setExpanded(isOpen ? null : control.id)}
                style={{
                  width: '100%',
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '0.9rem 1.5rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  textAlign: 'left',
                  color: 'inherit',
                }}
              >
                <span
                  style={{
                    flexShrink: 0,
                    minWidth: '108px',
                    textAlign: 'center',
                    fontSize: '0.72rem',
                    fontWeight: 600,
                    padding: '0.22rem 0.5rem',
                    borderRadius: '5px',
                    background: meta.bg,
                    color: meta.color,
                    border: `1px solid ${meta.color}33`,
                  }}
                >
                  {meta.label}
                </span>
                <span style={{ flex: 1, fontSize: '0.9rem', fontWeight: 500 }}>{control.title}</span>
                {evidence.length > 0 && (
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {evidence.length} подтв.
                  </span>
                )}
                <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{isOpen ? '▲' : '▼'}</span>
              </button>

              {isOpen && (
                <div
                  style={{
                    padding: '0 1.5rem 1.25rem 1.5rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.85rem',
                  }}
                >
                  <div style={{ fontSize: '0.84rem', color: '#e2e8f0', lineHeight: 1.55 }}>{control.summary}</div>

                  {control.risk && (
                    <div
                      style={{
                        fontSize: '0.8rem',
                        color: '#fca5a5',
                        padding: '0.6rem 0.85rem',
                        background: 'rgba(239, 68, 68, 0.08)',
                        border: '1px solid rgba(239, 68, 68, 0.25)',
                        borderRadius: '6px',
                      }}
                    >
                      <strong>Риск:</strong> {control.risk}
                    </div>
                  )}

                  {control.recommendation && (
                    <div style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>
                      <strong style={{ color: '#86efac' }}>Что сделать: </strong>
                      {control.recommendation}
                    </div>
                  )}

                  {evidence.length > 0 && (
                    <div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                        Подтверждение из кода:
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                        {evidence.map((item, index) => (
                          <div
                            key={index}
                            style={{
                              background: '#030712',
                              border: '1px solid var(--border-color)',
                              borderRadius: '5px',
                              padding: '0.5rem 0.7rem',
                              fontSize: '0.75rem',
                            }}
                          >
                            {onOpenFile && item.filePath ? (
                              <button
                                onClick={() => onOpenFile(item.filePath, item.line)}
                                style={{
                                  background: 'none', border: 'none', padding: 0, cursor: 'pointer',
                                  color: '#38bdf8', marginBottom: '2px', fontSize: 'inherit',
                                  fontFamily: 'inherit', textAlign: 'left', textDecoration: 'underline',
                                  textDecorationStyle: 'dotted', textUnderlineOffset: '2px',
                                }}
                                title="Открыть файл в редакторе"
                              >
                                {item.filePath}
                                {item.line ? `:${item.line}` : ''}
                              </button>
                            ) : (
                              <div style={{ color: '#38bdf8', marginBottom: '2px' }}>
                                {item.filePath}
                                {item.line ? `:${item.line}` : ''}
                              </div>
                            )}
                            <pre style={{ margin: 0, color: '#94a3b8', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                              {item.snippet}
                            </pre>
                            {item.note && (
                              <div style={{ color: 'var(--text-muted)', marginTop: '3px', fontStyle: 'italic' }}>
                                {item.note}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SecurityControlsPanel;
