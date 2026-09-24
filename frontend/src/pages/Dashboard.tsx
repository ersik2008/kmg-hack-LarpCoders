import { useEffect, useState } from 'react';
import { Activity, ShieldCheck, ShieldAlert, AlertTriangle, ArrowRight, RefreshCw } from 'lucide-react';
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
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: 700, margin: 0 }}>Обзор</h1>
          <p style={{ color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Обзор состояния безопасности и сканирований организации
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button onClick={fetchStats} className="btn btn-outline" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} /> Обновить
          </button>
          <button onClick={() => navigate('/repositories')} className="btn btn-primary">
            Сканировать репозиторий
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          Загрузка данных дашборда...
        </div>
      ) : error ? (
        <div className="card" style={{ border: '1px solid var(--danger)', color: 'var(--danger)', marginBottom: '2rem' }}>
          Не удалось загрузить данные: {error}
        </div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
            <StatCard 
              title="Репозиториев" 
              value={stats?.repositories ?? 0} 
              icon={<Activity size={24} color="var(--primary)" />} 
            />
            <StatCard 
              title="Всего сканирований" 
              value={stats?.totalScans ?? 0} 
              icon={<ShieldCheck size={24} color="var(--accent)" />} 
              subtitle={`${stats?.passScans ?? 0} успешно (PASS)`}
            />
            <StatCard 
              title="Критические риски" 
              value={stats?.criticalCount ?? 0} 
              icon={<ShieldAlert size={24} color="var(--danger)" />} 
              isAlert={Boolean(stats?.criticalCount && stats.criticalCount > 0)}
            />
            <StatCard 
              title="Высокие риски" 
              value={stats?.highCount ?? 0} 
              icon={<AlertTriangle size={24} color="var(--warning)" />} 
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem' }}>
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <h3 style={{ margin: 0 }}>Недавние сканирования</h3>
                <button onClick={() => navigate('/repositories')} className="btn btn-outline" style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
                  Все репозитории <ArrowRight size={14} style={{ marginLeft: '4px' }} />
                </button>
              </div>

              {(!stats?.recentScans || stats.recentScans.length === 0) ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  <p>Сканирований пока не было.</p>
                  <button onClick={() => navigate('/repositories')} className="btn btn-primary" style={{ marginTop: '0.75rem' }}>
                    Запустить первое сканирование
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {stats.recentScans.map((scan) => (
                    <ScanRow key={scan.id} scan={scan} onSelect={() => navigate(`/scans/${scan.id}`)} />
                  ))}
                </div>
              )}
            </div>

            <div className="card">
              <h3 style={{ marginBottom: '1.25rem' }}>Статистика уязвимостей</h3>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <VulnStatRow label="Критические" count={stats?.criticalCount ?? 0} badgeClass="badge-critical" />
                <VulnStatRow label="Высокие" count={stats?.highCount ?? 0} badgeClass="badge-high" />
                <VulnStatRow label="Средние" count={stats?.mediumCount ?? 0} badgeClass="badge-medium" />
                <VulnStatRow label="Низкие" count={stats?.lowCount ?? 0} badgeClass="badge" />
              </ul>

              <div style={{ marginTop: '2rem', padding: '1rem', background: 'var(--bg-dark)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Всего найдено уязвимостей</div>
                <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'white', marginTop: '0.25rem' }}>
                  {stats?.totalFindings ?? 0}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const StatCard = ({ title, value, icon, subtitle, isAlert }: any) => (
  <div 
    className="card" 
    style={{ 
      display: 'flex', 
      alignItems: 'center', 
      gap: '1.25rem',
      borderColor: isAlert ? 'rgba(239, 68, 68, 0.4)' : undefined,
    }}
  >
    <div style={{ background: 'var(--bg-dark)', padding: '0.9rem', borderRadius: 'var(--radius-md)', display: 'flex' }}>
      {icon}
    </div>
    <div>
      <h3 style={{ fontSize: '1.8rem', fontWeight: 700, margin: 0, lineHeight: 1.1 }}>{value}</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: '0.2rem', marginBottom: 0 }}>{title}</p>
      {subtitle && <span style={{ fontSize: '0.75rem', color: 'var(--accent)' }}>{subtitle}</span>}
    </div>
  </div>
);

const VulnStatRow = ({ label, count, badgeClass }: { label: string; count: number; badgeClass: string }) => (
  <li style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
    <span style={{ fontSize: '0.9rem', color: 'var(--text-main)' }}>{label}</span>
    <span className={`badge ${badgeClass}`}>{count}</span>
  </li>
);

const ScanRow = ({ scan, onSelect }: { scan: any; onSelect: () => void }) => {
  const repoName = scan.repository?.name || 'Repository';
  const time = new Date(scan.createdAt).toLocaleString();
  const status = scan.status;
  const policy = scan.policyResult;

  return (
    <div 
      onClick={onSelect}
      style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        padding: '0.9rem 1rem', 
        background: 'var(--bg-dark)', 
        borderRadius: 'var(--radius-sm)',
        cursor: 'pointer',
        border: '1px solid transparent',
        transition: 'border-color 0.2s',
      }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--border-color)')}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'transparent')}
    >
      <div>
        <h4 style={{ margin: 0, fontSize: '0.95rem' }}>{repoName}</h4>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{time}</span>
      </div>
      <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
        {policy && (
          <span className={`badge ${policy === 'PASS' ? 'badge-accent' : policy === 'BLOCK' ? 'badge-critical' : 'badge-warning'}`}>
            {policy}
          </span>
        )}
        <span className={`badge ${status === 'COMPLETED' ? 'badge-medium' : status === 'FAILED' ? 'badge-critical' : 'badge-warning'}`}>
          {status}
        </span>
      </div>
    </div>
  );
};

export default Dashboard;
