import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, Lock, Globe, GitPullRequestArrow, GitCommitHorizontal,
  RefreshCw, ShieldAlert, ShieldCheck, Shield, Star, AlertTriangle,
} from 'lucide-react';
import { useScanEvents } from '../hooks/useScanEvents';

const API = 'http://localhost:3000/api';

/**
 * Страховочный опрос. Основной канал обновлений — SSE: результат push-проверки
 * прилетает событием сразу, поэтому частый поллинг больше не нужен.
 */
const AUTO_REFRESH_MS = 120_000;

interface LastScan {
  id: string;
  status: string;
  policyResult: string | null;
  riskScore: number | null;
  completedAt: string | null;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
}

interface Repo {
  id: string;
  name: string;
  fullName: string;
  owner: string;
  isPrivate: boolean;
  language: string | null;
  description: string | null;
  url: string;
  defaultBranch: string;
  pushedAt: string | null;
  stars: number;
  openIssues: number;
  updatedAt: string;
  lastScan: LastScan | null;
}

interface PullRequest {
  number: number;
  title: string;
  authorLogin: string;
  authorAvatar: string | null;
  updatedAt: string;
  url: string;
}

interface Activity {
  lastCommit: {
    sha: string;
    message: string;
    authorLogin: string;
    authorAvatar: string | null;
    date: string | null;
  } | null;
  openPullRequests: PullRequest[];
  openPullRequestCount: number;
  error: string | null;
}

/** Результат проверки, прилетевший по SSE сразу после git push. */
interface PushEvent {
  repository: string | null;
  verdict: string | null;
  blocked: boolean;
  at: Date;
}

const authHeaders = (): HeadersInit => ({
  Authorization: `Bearer ${localStorage.getItem('kmg_token') || ''}`,
});

/** «5 мин назад» вместо голой даты — так активность читается с одного взгляда. */
const timeAgo = (iso: string | null): string => {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff)) return '—';

  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'только что';
  if (minutes < 60) return `${minutes} мин назад`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч назад`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} дн назад`;

  return new Date(iso).toLocaleDateString('ru-RU');
};

const Repositories = () => {
  const navigate = useNavigate();
  const [repos, setRepos] = useState<Repo[]>(() => {
    try {
      const cached = localStorage.getItem('kmg_repos_cache');
      return cached ? JSON.parse(cached) : [];
    } catch { return []; }
  });
  const [activity, setActivity] = useState<Record<string, Activity>>(() => {
    try {
      const cached = localStorage.getItem('kmg_activity_cache');
      return cached ? JSON.parse(cached) : {};
    } catch { return {}; }
  });
  const [loading, setLoading] = useState(() => !localStorage.getItem('kmg_repos_cache'));
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [startingScanId, setStartingScanId] = useState<string | null>(null);
  const [syncedAt, setSyncedAt] = useState<Date | null>(null);
  const [lastEvent, setLastEvent] = useState<PushEvent | null>(null);

  /**
   * Активность (коммиты и PR) грузится отдельно: это два вызова GitHub API на
   * репозиторий, и держать их на пути отрисовки списка нельзя.
   */
  const loadActivity = useCallback(async (list: Repo[]) => {
    const ids = list.slice(0, 40).map(r => r.id);
    if (ids.length === 0) return;

    try {
      const res = await fetch(`${API}/github/repositories/activity?ids=${ids.join(',')}`, {
        headers: authHeaders(),
      });
      if (!res.ok) return;
      const data = await res.json();
      setActivity(data);
      localStorage.setItem('kmg_activity_cache', JSON.stringify(data));
    } catch {
      /* активность — дополнение, её отсутствие не ломает страницу */
    }
  }, []);

  const sync = useCallback(async (background = false) => {
    if (!background && !localStorage.getItem('kmg_repos_cache')) setLoading(true);
    setSyncing(true);
    setError('');

    try {
      // Этот эндпоинт сам тянет список из GitHub и обновляет базу, поэтому
      // отдельная кнопка «Синхронизировать» не нужна.
      const res = await fetch(`${API}/github/repositories`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`Не удалось загрузить репозитории (HTTP ${res.status})`);

      const data: Repo[] = await res.json();
      setRepos(data);
      localStorage.setItem('kmg_repos_cache', JSON.stringify(data));
      setSyncedAt(new Date());
      loadActivity(data);
    } catch (err: any) {
      setError(err.message || 'Ошибка загрузки');
    } finally {
      setLoading(false);
      setSyncing(false);
    }
  }, [loadActivity]);

  useEffect(() => {
    sync();
    const timer = setInterval(() => sync(true), AUTO_REFRESH_MS);
    return () => clearInterval(timer);
  }, [sync]);

  // Живые обновления: результат проверки и завершение скана приходят событием.
  useScanEvents(event => {
    if (event.type === 'scan.completed') {
      setLastEvent({
        repository: event.payload?.repository || null,
        verdict: event.payload?.verdict || null,
        blocked: Boolean(event.payload?.blocked),
        at: new Date(),
      });
      sync(true);
    } else if (event.type === 'scan.progress' || event.type === 'repositories.synced') {
      sync(true);
    }
  });

  const handleScan = async (id: string) => {
    try {
      setStartingScanId(id);
      const res = await fetch(`${API}/scans`, {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ repositoryId: id }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.message || 'Не удалось запустить сканирование');
      }

      const data = await res.json();
      navigate(`/scans/${data.scanId || data.id}`);
    } catch (err: any) {
      setError(`Ошибка запуска сканирования: ${err.message}`);
    } finally {
      setStartingScanId(null);
    }
  };

  const filteredRepos = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return repos;
    return repos.filter(
      r =>
        r.name?.toLowerCase().includes(q) ||
        r.fullName?.toLowerCase().includes(q) ||
        r.language?.toLowerCase().includes(q) ||
        r.description?.toLowerCase().includes(q),
    );
  }, [repos, searchQuery]);

  const totals = useMemo(() => {
    const scanned = repos.filter(r => r.lastScan).length;
    const blocked = repos.filter(r => r.lastScan?.policyResult === 'BLOCK').length;
    const prs = Object.values(activity).reduce((sum, a) => sum + (a?.openPullRequestCount || 0), 0);
    return { total: repos.length, scanned, blocked, prs };
  }, [repos, activity]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1>Репозитории</h1>
          <p style={{ color: 'var(--text-muted)', margin: '0.25rem 0 0' }}>
            Список синхронизируется с GitHub автоматически
            {syncedAt && (
              <span style={{ fontSize: '0.8rem' }}> · обновлено {syncedAt.toLocaleTimeString('ru-RU')}</span>
            )}
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {syncing && (
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <RefreshCw size={14} /> синхронизация...
            </span>
          )}
          <StatChip label="всего" value={totals.total} />
          <StatChip label="проверено" value={totals.scanned} />
          {totals.blocked > 0 && <StatChip label="заблокировано" value={totals.blocked} danger />}
          {totals.prs > 0 && <StatChip label="открытых PR" value={totals.prs} />}
        </div>
      </div>

      {error && (
        <div className="card" style={{ border: '1px solid var(--danger)', color: '#fca5a5', marginBottom: '1.5rem', display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
          <AlertTriangle size={18} /> {error}
        </div>
      )}

      {/* Результат проверки последнего push — приходит по SSE в момент push. */}
      {lastEvent && (
        <div
          className="card"
          style={{
            marginBottom: '1.5rem',
            display: 'flex',
            gap: '0.6rem',
            alignItems: 'center',
            border: `1px solid ${lastEvent.blocked ? 'var(--danger)' : 'var(--border-color)'}`,
            color: lastEvent.blocked ? '#fca5a5' : 'var(--text-muted)',
          }}
        >
          {lastEvent.blocked ? <ShieldAlert size={18} /> : <ShieldCheck size={18} color="#86efac" />}
          <span>
            Проверка после push{lastEvent.repository ? ` · ${lastEvent.repository}` : ''}:{' '}
            <strong style={{ color: lastEvent.blocked ? '#fca5a5' : '#e2e8f0' }}>
              {lastEvent.blocked ? 'push заблокирован' : lastEvent.verdict || 'завершена'}
            </strong>
            <span style={{ fontSize: '0.75rem' }}> · {lastEvent.at.toLocaleTimeString('ru-RU')}</span>
          </span>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <div style={{ position: 'relative' }}>
            <Search style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} size={18} />
            <input
              type="text"
              placeholder="Поиск по названию, языку или описанию..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                width: '100%', padding: '0.75rem 1rem 0.75rem 2.5rem',
                background: 'var(--bg-dark)', border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)', color: 'white', outline: 'none',
              }}
            />
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            Загрузка репозиториев из GitHub...
          </div>
        ) : filteredRepos.length === 0 ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            {searchQuery ? 'Репозитории не найдены по запросу' : 'В аккаунте GitHub нет доступных репозиториев'}
          </div>
        ) : (
          <div>
            {filteredRepos.map(repo => (
              <RepoRow
                key={repo.id}
                repo={repo}
                activity={activity[repo.id]}
                scanning={startingScanId === repo.id}
                onScan={() => handleScan(repo.id)}
                onOpenScan={() => repo.lastScan && navigate(`/scans/${repo.lastScan.id}`)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

const StatChip = ({ label, value, danger }: { label: string; value: number; danger?: boolean }) => (
  <div
    style={{
      padding: '0.4rem 0.8rem', borderRadius: 'var(--radius-sm)',
      background: danger ? 'rgba(239, 68, 68, 0.1)' : 'var(--bg-surface)',
      border: `1px solid ${danger ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-color)'}`,
      textAlign: 'center', minWidth: '78px',
    }}
  >
    <div style={{ fontSize: '1.05rem', fontWeight: 700, color: danger ? '#fca5a5' : 'white' }}>{value}</div>
    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{label}</div>
  </div>
);

const ScanBadge = ({ scan }: { scan: LastScan | null }) => {
  if (!scan) {
    return (
      <span className="badge" style={{ background: 'var(--bg-surface-hover)', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
        <Shield size={12} /> не проверялся
      </span>
    );
  }

  if (scan.status === 'FAILED' || (scan.status === 'COMPLETED' && !scan.policyResult)) {
    return (
      <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
        <AlertTriangle size={12} /> проверка не завершена
      </span>
    );
  }

  if (scan.status !== 'COMPLETED') {
    return (
      <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.12)', color: '#38bdf8', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
        <RefreshCw size={12} /> сканируется
      </span>
    );
  }

  const isBlock = scan.policyResult === 'BLOCK';
  const isPass = scan.policyResult === 'PASS';

  return (
    <span
      className={`badge ${isBlock ? 'badge-critical' : isPass ? 'badge-accent' : 'badge-warning'}`}
      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
    >
      {isPass ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
      {scan.policyResult}
      {scan.totalFindings > 0 && ` · ${scan.totalFindings}`}
    </span>
  );
};

const RepoRow = ({
  repo, activity, scanning, onScan, onOpenScan,
}: {
  repo: Repo;
  activity?: Activity;
  scanning: boolean;
  onScan: () => void;
  onOpenScan: () => void;
}) => {
  const commit = activity?.lastCommit;
  const pulls = activity?.openPullRequests || [];

  return (
    <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '1.5rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
      <div style={{ flex: 1, minWidth: '320px', display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
          <a
            href={repo.url}
            target="_blank"
            rel="noreferrer"
            style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600, color: 'white', textDecoration: 'none' }}
          >
            {repo.fullName}
          </a>
          <span className="badge" style={{ background: 'var(--bg-surface-hover)', border: '1px solid var(--border-color)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            {repo.isPrivate ? <Lock size={11} /> : <Globe size={11} />}
            {repo.isPrivate ? 'Приватный' : 'Публичный'}
          </span>
          <ScanBadge scan={repo.lastScan} />
        </div>

        {repo.description && (
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', maxWidth: '60ch' }}>
            {repo.description}
          </div>
        )}

        <div style={{ display: 'flex', gap: '1rem', fontSize: '0.78rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
          {repo.language && <span>{repo.language}</span>}
          <span>ветка {repo.defaultBranch}</span>
          {repo.stars > 0 && (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
              <Star size={11} /> {repo.stars}
            </span>
          )}
          <span>последний пуш {timeAgo(repo.pushedAt)}</span>
        </div>

        {/* Кто последним пушил */}
        {commit && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', flexWrap: 'wrap' }}>
            <GitCommitHorizontal size={14} color="var(--text-muted)" />
            {commit.authorAvatar && (
              <img src={commit.authorAvatar} alt={commit.authorLogin} style={{ width: '18px', height: '18px', borderRadius: '50%' }} />
            )}
            <strong style={{ color: '#e2e8f0' }}>{commit.authorLogin}</strong>
            <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '38ch' }}>
              {commit.message}
            </span>
            <code style={{ fontSize: '0.7rem', color: '#38bdf8' }}>{commit.sha}</code>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>{timeAgo(commit.date)}</span>
          </div>
        )}

        {/* Кто открыл пулл-реквесты */}
        {pulls.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {pulls.slice(0, 3).map(pr => (
              <a
                key={pr.number}
                href={pr.url}
                target="_blank"
                rel="noreferrer"
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem', color: 'var(--text-muted)', textDecoration: 'none', flexWrap: 'wrap' }}
              >
                <GitPullRequestArrow size={13} color="#86efac" />
                <span style={{ color: '#86efac' }}>#{pr.number}</span>
                {pr.authorAvatar && (
                  <img src={pr.authorAvatar} alt={pr.authorLogin} style={{ width: '16px', height: '16px', borderRadius: '50%' }} />
                )}
                <strong style={{ color: '#cbd5e1' }}>{pr.authorLogin}</strong>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '36ch' }}>
                  {pr.title}
                </span>
                <span style={{ fontSize: '0.7rem' }}>{timeAgo(pr.updatedAt)}</span>
              </a>
            ))}
            {pulls.length > 3 && (
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                и ещё {pulls.length - 3} открытых PR
              </span>
            )}
          </div>
        )}

        {activity?.error && (
          <div style={{ fontSize: '0.72rem', color: 'var(--warning)' }}>
            Активность GitHub недоступна: {activity.error}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'stretch', minWidth: '150px' }}>
        <button onClick={onScan} className="btn btn-primary" disabled={scanning}>
          {scanning ? 'Запуск...' : 'Сканировать'}
        </button>
        {repo.lastScan && (
          <button onClick={onOpenScan} className="btn btn-outline" style={{ fontSize: '0.8rem' }}>
            Последний отчёт
          </button>
        )}
        {repo.lastScan?.completedAt && (
          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textAlign: 'center' }}>
            проверен {timeAgo(repo.lastScan.completedAt)}
          </span>
        )}
      </div>
    </div>
  );
};

export default Repositories;
