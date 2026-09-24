import { useEffect, useState } from 'react';
import { Activity, ShieldCheck, ShieldAlert, AlertTriangle, ArrowRight, RefreshCw, GitBranch } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface DashboardStats {
  repositories: number;
  totalScans: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  passScans: number;
  blockScans: number;
  recentScans: Array<{
    id: string;
    status: string;
    riskScore?: number | null;
    policyResult?: string | null;
    createdAt: string;
    repository?: {
      name: string;
    };
  }>;
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchStats = async () => {
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('kmg_token');
      const response = await fetch('http://localhost:3000/api/dashboard/stats', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch dashboard statistics');
      }

      const data = await response.json();
      setStats(data);
    } catch (err: any) {
      setError(err.message || 'Error loading dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  return (
    <div className="dashboard">
      {/* Page header */}
      <div className="dashboard-header">
        <div className="dashboard-header-title">
          <h1>Обзор</h1>
          <p>Обзор состояния безопасности и сканирований организации</p>
        </div>
        <div className="dashboard-header-actions">
          <button onClick={fetchStats} className="ds-btn ds-btn-secondary">
            <RefreshCw size={15} strokeWidth={1.5} />
            Обновить
          </button>
          <button onClick={() => navigate('/repositories')} className="ds-btn ds-btn-primary">
            Сканировать репозиторий
          </button>
        </div>
      </div>

      {loading ? (
        <div className="dashboard-loading">Загрузка данных...</div>
      ) : error ? (
        <div className="ds-card dashboard-error">
          Не удалось загрузить данные: {error}
        </div>
      ) : (
        <>
          {/* Metric cards */}
          <div className="stat-grid">
            <StatCard
              title="Репозиториев"
              value={stats?.repositories ?? 0}
              icon={<Activity size={18} strokeWidth={1.5} />}
              variant="neutral"
            />
            <StatCard
              title="Всего сканирований"
              value={stats?.totalScans ?? 0}
              icon={<ShieldCheck size={18} strokeWidth={1.5} />}
              subtitle={`${stats?.passScans ?? 0} успешно (PASS)`}
              variant="success"
            />
            <StatCard
              title="Критические риски"
              value={stats?.criticalCount ?? 0}
              icon={<ShieldAlert size={18} strokeWidth={1.5} />}
              variant="critical"
            />
            <StatCard
              title="Высокие риски"
              value={stats?.highCount ?? 0}
              icon={<AlertTriangle size={18} strokeWidth={1.5} />}
              variant="high"
            />
          </div>

          {/* Main content grid */}
          <div className="dashboard-grid">
            {/* Recent scans */}
            <div className="ds-card">
              <div className="ds-card-header">
                <h3 className="ds-card-title">Недавние сканирования</h3>
                <button onClick={() => navigate('/repositories')} className="ds-link-btn">
                  Все репозитории <ArrowRight size={14} />
                </button>
              </div>

              {(!stats?.recentScans || stats.recentScans.length === 0) ? (
                <div className="dashboard-empty">
                  <p>Сканирований пока не было.</p>
                  <button onClick={() => navigate('/repositories')} className="ds-btn ds-btn-primary" style={{ marginTop: '0.75rem' }}>
                    Запустить первое сканирование
                  </button>
                </div>
              ) : (
                <div className="scan-list">
                  {stats.recentScans.map((scan) => (
                    <ScanRow key={scan.id} scan={scan} onSelect={() => navigate(`/scans/${scan.id}`)} />
                  ))}
                </div>
              )}
            </div>

            {/* Vulnerability stats */}
            <div className="ds-card">
              <div className="ds-card-header">
                <h3 className="ds-card-title">Статистика уязвимостей</h3>
              </div>
              <ul className="vuln-list">
                <VulnStatRow label="Критические" count={stats?.criticalCount ?? 0} variant="critical" />
                <VulnStatRow label="Высокие" count={stats?.highCount ?? 0} variant="high" />
                <VulnStatRow label="Средние" count={stats?.mediumCount ?? 0} variant="medium" />
                <VulnStatRow label="Низкие" count={stats?.lowCount ?? 0} variant="low" />
              </ul>

              <div className="vuln-total">
                <div className="vuln-total-label">Всего найдено уязвимостей</div>
                <div className="vuln-total-value">{stats?.totalFindings ?? 0}</div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const StatCard = ({ title, value, icon, subtitle, variant }: {
  title: string;
  value: number;
  icon: React.ReactNode;
  subtitle?: string;
  variant: 'neutral' | 'success' | 'critical' | 'high';
}) => (
  <div className={`stat-card stat-card--${variant}`}>
    <div className={`stat-card-icon stat-card-icon--${variant}`}>
      {icon}
    </div>
    <div className="stat-card-body">
      <div className="stat-card-value">{value}</div>
      <div className="stat-card-title">{title}</div>
      {subtitle && <div className="stat-card-subtitle">{subtitle}</div>}
    </div>
  </div>
);

const VulnStatRow = ({ label, count, variant }: { label: string; count: number; variant: 'critical' | 'high' | 'medium' | 'low' }) => (
  <li className="vuln-row">
    <div className="vuln-row-left">
      <span className={`vuln-dot vuln-dot--${variant}`}></span>
      <span className="vuln-row-label">{label}</span>
    </div>
    <span className="vuln-row-count">{count}</span>
  </li>
);

const ScanRow = ({ scan, onSelect }: { scan: any; onSelect: () => void }) => {
  const repoName = scan.repository?.name || 'Repository';
  const time = new Date(scan.createdAt).toLocaleString('ru-RU');
  const status = scan.status;
  const policy = scan.policyResult;

  return (
    <div className="scan-row" onClick={onSelect}>
      <div className="scan-row-icon">
        <GitBranch size={16} strokeWidth={1.5} />
      </div>
      <div className="scan-row-info">
        <div className="scan-row-name">{repoName}</div>
        <div className="scan-row-time">{time}</div>
      </div>
      <div className="scan-row-badges">
        {policy && (
          <span className={`ds-badge ds-badge--${policy === 'PASS' ? 'success' : policy === 'BLOCK' ? 'danger' : 'warning'}`}>
            {policy}
          </span>
        )}
        <span className={`ds-badge ds-badge--${status === 'COMPLETED' ? 'neutral' : status === 'FAILED' ? 'danger' : 'warning'}`}>
          {status}
        </span>
      </div>
      <div className="scan-row-arrow">
        <ArrowRight size={14} />
      </div>
    </div>
  );
};

export default Dashboard;
