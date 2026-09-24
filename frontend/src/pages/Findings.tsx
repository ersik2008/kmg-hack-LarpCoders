import { useCallback, useEffect, useState } from 'react';
import { ShieldAlert, Search, AlertTriangle, ShieldCheck, Info, ExternalLink, ChevronDown, ChevronUp, RefreshCw, Sparkles, Code } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import RepositoryPicker from '../components/RepositoryPicker';
import type { ScannedRepository } from '../components/RepositoryPicker';
import { useScanEvents } from '../hooks/useScanEvents';

const API = 'http://localhost:3000/api';

interface Finding {
  id: string;
  scanner: string;
  ruleId: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: string;
  title: string;
  description: string | null;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  codeSnippet: string | null;
  category: string | null;
  createdAt: string;
  scanId: string;
  /** Вердикт AI-агента по этой находке, если разбор выполнялся. */
  aiVerdict?: {
    verdict?: string;
    confidence?: string;
    reason?: string;
    recommendation?: string;
  } | null;
}

interface ScanSummary {
  id: string;
  branch: string | null;
  commitSha: string | null;
  completedAt: string | null;
  policyResult: string | null;
  riskScore: number | null;
  repository: { id: string; name: string; fullName: string } | null;
}

const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/** Цвет уровня критичности — общий для полосы распределения и фильтров. */
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#10b981',
  LOW: '#6366f1',
  INFO: '#64748b',
};

const VERDICT_LABEL: Record<string, { label: string; color: string; bg: string; border: string }> = {
  TRUE_POSITIVE: { label: 'Подтверждено', color: '#fca5a5', bg: 'rgba(239, 68, 68, 0.12)', border: 'rgba(239, 68, 68, 0.3)' },
  FALSE_POSITIVE: { label: 'Ложное', color: '#6ee7b7', bg: 'rgba(16, 185, 129, 0.12)', border: 'rgba(16, 185, 129, 0.3)' },
  UNCERTAIN: { label: 'Требует проверки', color: '#fcd34d', bg: 'rgba(245, 158, 11, 0.12)', border: 'rgba(245, 158, 11, 0.3)' },
};

const authHeaders = (): HeadersInit => ({
  Authorization: `Bearer ${localStorage.getItem('kmg_token') || ''}`,
});

const severityIcon = (severity: string) => {
  switch (severity) {
    case 'CRITICAL': return <ShieldAlert size={16} color="#fca5a5" />;
    case 'HIGH': return <AlertTriangle size={16} color="#fcd34d" />;
    case 'MEDIUM': return <ShieldCheck size={16} color="#6ee7b7" />;
    case 'LOW': return <Info size={16} color="#a5b4fc" />;
    default: return <Info size={16} color="var(--text-muted)" />;
  }
};

const Findings = () => {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [repositories, setRepositories] = useState<ScannedRepository[]>([]);
  const [activeRepoId, setActiveRepoId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchFindings = useCallback(async (repositoryId: string | null) => {
    setLoading(true);
    setError('');
    try {
      const url = repositoryId
        ? `${API}/scans/findings/latest?repositoryId=${encodeURIComponent(repositoryId)}`
        : `${API}/scans/findings/latest`;

      const response = await fetch(url, { headers: authHeaders() });
      if (!response.ok) throw new Error('Не удалось получить уязвимости');

      const data = await response.json();
      const list: Finding[] = data.findings || [];
      list.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

      setFindings(list);
      setScan(data.scan || null);
    } catch (err: any) {
      setError(err.message || 'Ошибка загрузки');
    } finally {
      setLoading(false);
    }
  }, []);

  // Переключатель строится по репозиториям с завершёнными сканами; первый в
  // списке — тот, который сканировали последним.
  useEffect(() => {
    const loadRepositories = async () => {
      try {
        const res = await fetch(`${API}/graph/attack-paths/repositories`, { headers: authHeaders() });
        if (!res.ok) return;
        const data: ScannedRepository[] = await res.json();
        setRepositories(data);
        if (data.length > 0) setActiveRepoId(prev => prev ?? data[0].id);
      } catch {
        /* переключатель — дополнение: без него страница всё равно работает */
      }
    };

    loadRepositories();
  }, []);

  useEffect(() => {
    fetchFindings(activeRepoId);
  }, [activeRepoId, fetchFindings]);

  // Завершился скан показываемого репозитория — список перечитывается сам.
  useScanEvents(event => {
    if (event.type !== 'scan.completed') return;
    if (!activeRepoId || event.repositoryId === activeRepoId) fetchFindings(activeRepoId);
  });

  /**
   * Переход к коду находки: открывает отчёт сканирования с уже выбранным
   * файлом и подсвеченной строкой — контекст сохраняется, а не теряется.
   */
  const openFindingInCode = (finding: Finding) => {
    if (!finding.filePath) return;
    const params = new URLSearchParams({ file: finding.filePath });
    if (finding.startLine) params.set('line', String(finding.startLine));
    navigate(`/scans/${finding.scanId}?${params.toString()}`);
  };

  const filtered = findings.filter(f => {
    const matchesSeverity = filterSeverity === 'ALL' || f.severity === filterSeverity;
    const matchesSearch = !searchQuery || 
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.filePath && f.filePath.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (f.category && f.category.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSeverity && matchesSearch;
  });

  const counts = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.8rem', fontWeight: 700 }}>Все уязвимости</h1>
          <p style={{ color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {scan?.repository
              ? <>Последнее сканирование <strong style={{ color: '#cbd5e1' }}>{scan.repository.fullName}</strong>{scan.branch ? <> · ветка {scan.branch}</> : null}</>
              : 'Обнаруженные проблемы безопасности'}
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <RepositoryPicker
            repositories={repositories}
            activeId={activeRepoId}
            onChange={setActiveRepoId}
          />
          {scan?.id && (
            <button
              onClick={() => navigate(`/scans/${scan.id}`)}
              className="btn btn-outline"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', height: '42px' }}
            >
              Отчёт сканирования <ExternalLink size={14} />
            </button>
          )}
          <button
            onClick={() => fetchFindings(activeRepoId)}
            className="btn btn-outline"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', height: '42px' }}
          >
            <RefreshCw size={16} /> Обновить
          </button>
        </div>
      </div>

      {/* Распределение по критичности.
          Пять крупных карточек с числами занимали целый экран и не показывали
          соотношение. Полоса делает пропорции видимыми сразу, а подписи под ней
          работают как фильтр — то же действие, но в разы компактнее. */}
      {findings.length > 0 && (
        <div className="card" style={{ padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '0.7rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Распределение по критичности
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              всего <strong style={{ color: 'white', fontSize: '1rem' }}>{findings.length}</strong>
            </span>
          </div>

          <div style={{ display: 'flex', height: '10px', borderRadius: '999px', overflow: 'hidden', background: 'var(--bg-dark)', marginBottom: '0.8rem' }}>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map(sev => (
              counts[sev] > 0 && (
                <div
                  key={sev}
                  title={`${sev}: ${counts[sev]}`}
                  style={{
                    width: `${(counts[sev] / findings.length) * 100}%`,
                    background: SEVERITY_COLORS[sev],
                    opacity: filterSeverity === 'ALL' || filterSeverity === sev ? 1 : 0.28,
                    transition: 'opacity 0.15s ease',
                  }}
                />
              )
            ))}
          </div>

          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
            <button
              onClick={() => setFilterSeverity('ALL')}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
                padding: '0.28rem 0.65rem', borderRadius: '999px', cursor: 'pointer',
                fontSize: '0.75rem', fontWeight: 600,
                background: filterSeverity === 'ALL' ? 'rgba(148, 163, 184, 0.18)' : 'var(--bg-dark)',
                border: `1px solid ${filterSeverity === 'ALL' ? '#94a3b8' : 'var(--border-color)'}`,
                color: filterSeverity === 'ALL' ? '#e2e8f0' : 'var(--text-muted)',
              }}
            >
              Все <span style={{ opacity: 0.8 }}>{findings.length}</span>
            </button>

            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map(sev => {
              const isActive = filterSeverity === sev;
              const isEmpty = counts[sev] === 0;
              return (
                <button
                  key={sev}
                  onClick={() => !isEmpty && setFilterSeverity(isActive ? 'ALL' : sev)}
                  disabled={isEmpty}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
                    padding: '0.28rem 0.65rem', borderRadius: '999px',
                    cursor: isEmpty ? 'default' : 'pointer',
                    fontSize: '0.75rem', fontWeight: 600,
                    background: isActive ? `${SEVERITY_COLORS[sev]}22` : 'var(--bg-dark)',
                    border: `1px solid ${isActive ? SEVERITY_COLORS[sev] : 'var(--border-color)'}`,
                    color: isEmpty ? '#475569' : isActive ? SEVERITY_COLORS[sev] : 'var(--text-muted)',
                    opacity: isEmpty ? 0.45 : 1,
                    transition: 'all 0.15s ease',
                  }}
                >
                  <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: SEVERITY_COLORS[sev], opacity: isEmpty ? 0.4 : 1 }} />
                  {sev} <span style={{ opacity: 0.8 }}>{counts[sev]}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Search & filter bar */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} size={18} />
            <input
              type="text"
              placeholder="Поиск по названию, пути файла, категории..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%', padding: '0.75rem 1rem 0.75rem 2.5rem',
                background: 'var(--bg-dark)', border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)', color: 'white', outline: 'none'
              }}
            />
          </div>
          {/* Фильтр по критичности живёт в полосе распределения выше —
              дублировать его селектом незачем. */}
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            Показано: <strong style={{ color: 'white' }}>{filtered.length}</strong> из {findings.length}
          </span>
        </div>

        {/* Findings list */}
        {loading ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>Загрузка уязвимостей...</div>
        ) : error ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--danger)' }}>Ошибка: {error}</div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <ShieldCheck size={48} style={{ margin: '0 auto 1rem auto', color: 'var(--accent)', opacity: 0.8 }} />
            <p>Уязвимости по заданным критериям не найдены.</p>
          </div>
        ) : (
          <div>
            {filtered.map(finding => (
              <div key={finding.id} style={{
                padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)',
                transition: 'background 0.2s',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                  <div style={{ display: 'flex', gap: '1rem', flex: 1 }}>
                    <div style={{ marginTop: '2px' }}>{severityIcon(finding.severity)}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem', flexWrap: 'wrap' }}>
                        <h4 style={{ margin: 0, fontSize: '1rem', color: 'white' }}>{finding.title}</h4>
                        <span className={`badge badge-${finding.severity.toLowerCase()}`}>
                          {finding.severity}
                        </span>
                        {/* Вердикт AI сразу в списке: он определяет, стоит ли
                            вообще разбираться с этой находкой. */}
                        {finding.aiVerdict?.verdict && VERDICT_LABEL[finding.aiVerdict.verdict] && (
                          <span
                            title={finding.aiVerdict.reason || undefined}
                            style={{
                              display: 'inline-flex', alignItems: 'center', gap: '4px',
                              padding: '0.1rem 0.45rem', borderRadius: '999px',
                              fontSize: '0.65rem', fontWeight: 600,
                              background: VERDICT_LABEL[finding.aiVerdict.verdict].bg,
                              border: `1px solid ${VERDICT_LABEL[finding.aiVerdict.verdict].border}`,
                              color: VERDICT_LABEL[finding.aiVerdict.verdict].color,
                            }}
                          >
                            <Sparkles size={10} /> {VERDICT_LABEL[finding.aiVerdict.verdict].label}
                          </span>
                        )}
                      </div>
                      {finding.filePath && (
                        /* Клик ведёт в редактор сканирования ровно на строку
                           находки, а не просто «в файл». */
                        <button
                          onClick={() => openFindingInCode(finding)}
                          title="Открыть код на этой строке"
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
                            background: 'none', border: 'none', padding: 0, margin: '0.25rem 0',
                            fontSize: '0.85rem', color: '#60a5fa', fontFamily: 'monospace',
                            cursor: 'pointer', textAlign: 'left',
                            textDecoration: 'underline', textDecorationStyle: 'dotted',
                            textUnderlineOffset: '3px',
                          }}
                        >
                          <Code size={13} />
                          {finding.filePath}{finding.startLine ? `:${finding.startLine}` : ''}
                        </button>
                      )}
                      {finding.description && (
                        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', margin: '0.25rem 0', maxWidth: '700px' }}>
                          {finding.description}
                        </p>
                      )}
                      <div style={{ display: 'flex', gap: '1.25rem', marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        <span>Сканер: <strong>{finding.scanner}</strong></span>
                        {finding.category && <span>Категория: {finding.category}</span>}
                        <span>Обнаружено: {new Date(finding.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    {(finding.codeSnippet || finding.aiVerdict?.recommendation) && (
                      <button
                        onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        className="btn btn-outline"
                        style={{ fontSize: '0.8rem', padding: '0.35rem 0.7rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                      >
                        Детали {expandedId === finding.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    )}
                    {finding.scanId && (
                      <button
                        onClick={() => navigate(`/scans/${finding.scanId}`)}
                        className="btn btn-outline"
                        style={{ fontSize: '0.8rem', padding: '0.35rem 0.7rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                        title="Открыть сканирование"
                      >
                        Граф <ExternalLink size={14} />
                      </button>
                    )}
                  </div>
                </div>

                {expandedId === finding.id && (
                  <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {finding.codeSnippet && (
                      <div style={{ padding: '0.75rem 1rem', background: '#050505', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>Фрагмент исходного кода:</div>
                        <pre style={{ margin: 0, fontSize: '0.8rem', color: '#38bdf8', overflowX: 'auto', fontFamily: 'monospace' }}>
                          {finding.codeSnippet}
                        </pre>
                      </div>
                    )}

                    {finding.aiVerdict?.recommendation && (
                      <div style={{ padding: '0.75rem 1rem', background: 'rgba(2, 6, 23, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                          <Sparkles size={13} color="#a5b4fc" />
                          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#86efac' }}>Что сделать</span>
                        </div>
                        <div style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>{finding.aiVerdict.recommendation}</div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Findings;

