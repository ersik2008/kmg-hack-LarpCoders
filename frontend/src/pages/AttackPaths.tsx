import { useEffect, useState, Fragment, useCallback } from 'react';
import { ArrowRight, ExternalLink, RefreshCw, Shield, Code } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import RepositoryPicker from '../components/RepositoryPicker';
import type { ScannedRepository } from '../components/RepositoryPicker';
import { useScanEvents } from '../hooks/useScanEvents';

const API = 'http://localhost:3000/api';

interface AttackPathNode {
  order: number;
  graphNode: {
    label: string;
    type: string;
    filePath?: string | null;
    line?: number | null;
  };
}

interface AttackPathItem {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: string;
  impact?: string;
  remediation?: string;
  scanId: string;
  createdAt: string;
  scan?: {
    completedAt?: string | null;
    createdAt?: string;
    repository?: {
      name: string;
      fullName?: string;
    };
  };
  nodes: AttackPathNode[];
}

const authHeaders = (): HeadersInit => ({
  Authorization: `Bearer ${localStorage.getItem('kmg_token') || ''}`,
});

const AttackPaths = () => {
  const navigate = useNavigate();
  const [paths, setPaths] = useState<AttackPathItem[]>([]);
  const [repositories, setRepositories] = useState<ScannedRepository[]>([]);
  // null — «последний сканированный»: выбор ещё не сделан пользователем.
  const [activeRepoId, setActiveRepoId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const fetchAttackPaths = useCallback(async (repositoryId: string | null) => {
    setLoading(true);
    setError('');
    try {
      const url = repositoryId
        ? `${API}/graph/attack-paths?repositoryId=${encodeURIComponent(repositoryId)}`
        : `${API}/graph/attack-paths`;

      const res = await fetch(url, { headers: authHeaders() });
      if (!res.ok) {
        throw new Error('Failed to load attack paths');
      }
      const data = await res.json();
      setPaths(data);
    } catch (err: any) {
      setError(err.message || 'Ошибка загрузки векторов атак');
    } finally {
      setLoading(false);
    }
  }, []);

  // Список репозиториев грузится один раз: по нему строится переключатель,
  // а первый в списке — это репозиторий с самым свежим сканом.
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
    fetchAttackPaths(activeRepoId);
  }, [activeRepoId, fetchAttackPaths]);

  useScanEvents(event => {
    if (event.type !== 'scan.completed') return;
    if (!activeRepoId || event.repositoryId === activeRepoId) fetchAttackPaths(activeRepoId);
  });


  /** Переход к строке кода, из которой взят узел цепочки. */
  const openNodeInCode = (scanId: string, filePath?: string | null, line?: number | null) => {
    if (!filePath) return;
    const params = new URLSearchParams({ file: filePath });
    if (line) params.set('line', String(line));
    navigate(`/scans/${scanId}?${params.toString()}`);
  };

  const filteredPaths = paths.filter(p => {
    if (selectedSeverity === 'ALL') return true;
    return p.severity === selectedSeverity;
  });

  const activeRepo = repositories.find(r => r.id === activeRepoId) || null;
  // Все цепочки относятся к одному скану, поэтому ссылку на него берём из первой.
  const shownScanId = paths[0]?.scanId || activeRepo?.lastScanId || null;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.8rem', fontWeight: 700 }}>Цепочки атак</h1>
          <p style={{ color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {activeRepo
              ? <>Маршруты эксплуатации по последнему сканированию <strong style={{ color: '#cbd5e1' }}>{activeRepo.fullName || activeRepo.name}</strong></>
              : 'Цепочки уязвимостей и маршруты эксплуатации от точки входа до целевого компонента'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <RepositoryPicker
            repositories={repositories}
            activeId={activeRepoId}
            onChange={setActiveRepoId}
          />
          {shownScanId && (
            <button
              onClick={() => navigate(`/scans/${shownScanId}`)}
              className="btn btn-outline"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', height: '42px' }}
            >
              Отчёт сканирования <ExternalLink size={14} />
            </button>
          )}
          <button
            onClick={() => fetchAttackPaths(activeRepoId)}
            className="btn btn-outline"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', height: '42px' }}
          >
            <RefreshCw size={16} /> Обновить
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
          <button
            key={sev}
            onClick={() => setSelectedSeverity(sev)}
            className="btn"
            style={{
              fontSize: '0.85rem',
              padding: '0.4rem 0.9rem',
              background: selectedSeverity === sev ? 'var(--primary)' : 'var(--bg-surface)',
              border: '1px solid var(--border-color)',
              color: 'white',
            }}
          >
            {sev === 'ALL' ? 'Все уровни' : sev}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          Загрузка цепочек атак...
        </div>
      ) : error ? (
        <div className="card" style={{ border: '1px solid var(--danger)', color: 'var(--danger)' }}>
          Ошибка: {error}
        </div>
      ) : filteredPaths.length === 0 ? (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <Shield size={36} style={{ margin: '0 auto 1rem auto', color: 'var(--accent)' }} />
          <h3>
            {paths.length > 0
              ? 'Нет цепочек выбранного уровня'
              : activeRepo
                ? `В репозитории ${activeRepo.name} цепочек атак не найдено`
                : 'Опасных цепочек атак не обнаружено'}
          </h3>
          <p>
            {paths.length > 0
              ? 'Смените фильтр критичности, чтобы увидеть остальные цепочки.'
              : 'Либо сканирования ещё не проводились, либо связей между уязвимостями не обнаружено.'}
          </p>
          {paths.length === 0 && (
            <button onClick={() => navigate('/repositories')} className="btn btn-primary" style={{ marginTop: '1rem' }}>
              Перейти к репозиториям
            </button>
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {filteredPaths.map((path) => (
            <div 
              key={path.id} 
              className="card" 
              style={{ 
                borderLeft: `4px solid ${path.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)'}`,
                padding: '1.5rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                    <span className={`badge badge-${path.severity.toLowerCase()}`}>
                      {path.severity}
                    </span>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Уверенность: <strong>{path.confidence}</strong>
                    </span>
                    {/* Репозиторий показан в шапке страницы и одинаков для всех
                        цепочек списка, поэтому здесь полезнее число шагов. */}
                    {path.nodes?.length > 0 && (
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        Шагов: <strong>{path.nodes.length}</strong>
                      </span>
                    )}
                  </div>
                  <h3 style={{ margin: '0 0 0.4rem 0', fontSize: '1.2rem', color: 'white' }}>
                    {path.title}
                  </h3>
                  <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                    {path.description}
                  </p>
                </div>

                <button 
                  onClick={() => navigate(`/scans/${path.scanId}`)} 
                  className="btn btn-outline"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}
                >
                  Открыть граф <ExternalLink size={14} />
                </button>
              </div>

              {/* Visual Node Path Chain */}
              {path.nodes && path.nodes.length > 0 && (
                <div style={{ 
                  background: 'var(--bg-dark)', 
                  padding: '1rem', 
                  borderRadius: 'var(--radius-sm)', 
                  margin: '1rem 0',
                  display: 'flex',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '0.75rem'
                }}>
                  {path.nodes.map((n, i) => {
                    const nodeFile = n.graphNode?.filePath;
                    const isClickable = Boolean(nodeFile);
                    return (
                    <Fragment key={i}>
                      <div
                        onClick={() => isClickable && openNodeInCode(path.scanId, nodeFile, n.graphNode?.line)}
                        title={isClickable ? `Открыть ${nodeFile}${n.graphNode?.line ? `:${n.graphNode.line}` : ''}` : undefined}
                        style={{
                        padding: '0.4rem 0.8rem',
                        borderRadius: '6px',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.35rem',
                        cursor: isClickable ? 'pointer' : 'default',
                        background: i === 0 ? 'rgba(59, 130, 246, 0.2)' : i === path.nodes.length - 1 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255, 255, 255, 0.05)',
                        border: `1px solid ${i === 0 ? '#3b82f6' : i === path.nodes.length - 1 ? '#ef4444' : 'var(--border-color)'}`,
                        color: i === 0 ? '#93c5fd' : i === path.nodes.length - 1 ? '#fca5a5' : 'var(--text-main)',
                      }}>
                        {isClickable && <Code size={12} style={{ opacity: 0.75 }} />}
                        <span>{n.graphNode?.label || `Node ${i + 1}`}</span>
                      </div>
                      {i < path.nodes.length - 1 && (
                        <ArrowRight size={14} style={{ color: 'var(--text-muted)' }} />
                      )}
                    </Fragment>
                    );
                  })}
                </div>
              )}

              {/* Impact & Remediation */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem', fontSize: '0.85rem' }}>
                {path.impact && (
                  <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: 'var(--radius-sm)' }}>
                    <strong style={{ color: '#fca5a5', display: 'block', marginBottom: '0.25rem' }}>Потенциальное влияние:</strong>
                    <span style={{ color: 'var(--text-muted)' }}>{path.impact}</span>
                  </div>
                )}
                {path.remediation && (
                  <div style={{ padding: '0.75rem', background: 'rgba(34, 197, 94, 0.05)', border: '1px solid rgba(34, 197, 94, 0.2)', borderRadius: 'var(--radius-sm)' }}>
                    <strong style={{ color: '#86efac', display: 'block', marginBottom: '0.25rem' }}>Рекомендация по исправлению:</strong>
                    <span style={{ color: 'var(--text-muted)' }}>{path.remediation}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AttackPaths;
