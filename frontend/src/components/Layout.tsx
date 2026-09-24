import React, { useEffect, useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderGit2, ShieldAlert, Settings, LogOut, Shield, GitFork, User as UserIcon } from 'lucide-react';
import ConfirmDialog from './ConfirmDialog';

interface UserProfile {
  id: string;
  name?: string | null;
  email?: string | null;
  avatarUrl?: string | null;
  githubAccount?: {
    login: string;
    avatarUrl?: string | null;
  } | null;
}

const Layout = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);
  const [confirmLogout, setConfirmLogout] = useState(false);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const token = localStorage.getItem('kmg_token');
        if (!token) return;

        const res = await fetch('http://localhost:3000/api/auth/me', {
          headers: { Authorization: `Bearer ${token}` }
        });

        if (res.ok) {
          const data = await res.json();
          setUser(data);
          // Trigger the backend's cached AI-key health check on first entry to
          // the authenticated app. The Settings page can display its result.
          void fetch('http://localhost:3000/api/system/status', {
            headers: { Authorization: 'Bearer ' + token },
          });
        } else if (res.status === 401) {
          // Session was revoked server-side (logout elsewhere / token cleared).
          localStorage.removeItem('kmg_token');
          navigate('/login', { replace: true });
        }
      } catch (err) {
        console.error('Failed to fetch user profile', err);
      }
    };

    fetchUser();
  }, [navigate]);

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);

    const token = localStorage.getItem('kmg_token');

    // Ask the backend to revoke the GitHub OAuth token/grant and kill the
    // server-side session. Local cleanup happens even if this call fails.
    try {
      if (token) {
        await fetch('http://localhost:3000/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        });
      }
    } catch (err) {
      console.error('Logout request failed, clearing local session anyway', err);
    }

    try {
      localStorage.removeItem('kmg_token');
      localStorage.clear();
      sessionStorage.clear();
    } catch (err) {
      console.error('Failed to clear local storage', err);
    }

    // replace() instead of navigate() so the OAuth callback URL (which still
    // carries ?token=... in the history stack) cannot be restored with "Back".
    window.location.replace('/login');
  };

  const avatar = user?.avatarUrl || user?.githubAccount?.avatarUrl;
  const displayName = user?.name || user?.githubAccount?.login || 'Пользователь';
  const displayLogin = user?.githubAccount?.login ? `@${user.githubAccount.login}` : user?.email || 'GitHub User';

  return (
    <div className="app-container">
      <aside style={{
        width: '260px',
        backgroundColor: 'var(--bg-surface)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        padding: '1.5rem 1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '2.5rem', padding: '0 0.5rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--primary), #4f46e5)',
            width: '40px', height: '40px', borderRadius: '10px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 4px 15px var(--primary-glow)'
          }}>
            <Shield color="white" size={24} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.25rem', margin: 0, fontWeight: 700, letterSpacing: '0.05em' }}>KMG AI</h2>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Security Agent</span>
          </div>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
          <NavItem to="/dashboard" icon={<LayoutDashboard size={20} />} label="Обзор" />
          <NavItem to="/repositories" icon={<FolderGit2 size={20} />} label="Репозитории" />
          <NavItem to="/attack-paths" icon={<GitFork size={20} />} label="Цепочки атак" />
          <NavItem to="/findings" icon={<ShieldAlert size={20} />} label="Все уязвимости" />
          <NavItem to="/settings" icon={<Settings size={20} />} label="Настройки" />
        </nav>

        {/* User Profile & Logout */}
        <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border-color)', paddingTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem' }}>
            {avatar ? (
              <img 
                src={avatar} 
                alt={displayName} 
                style={{ width: '36px', height: '36px', borderRadius: '50%', objectFit: 'cover', border: '1px solid var(--border-color)' }} 
              />
            ) : (
              <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'var(--bg-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border-color)' }}>
                <UserIcon size={18} color="var(--text-muted)" />
              </div>
            )}
            <div style={{ overflow: 'hidden' }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'white', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                {displayName}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                {displayLogin}
              </div>
            </div>
          </div>

          <button 
            onClick={() => setConfirmLogout(true)} 
            disabled={loggingOut}
            className="btn btn-outline" 
            style={{ width: '100%', justifyContent: 'flex-start', color: 'var(--danger)', border: '1px solid rgba(239, 68, 68, 0.2)', fontSize: '0.85rem', opacity: loggingOut ? 0.6 : 1 }}
          >
            <LogOut size={16} style={{ marginRight: '0.5rem' }} /> {loggingOut ? 'Выход...' : 'Выйти'}
          </button>
        </div>
      </aside>
      
      <main className="main-content animate-in">
        <Outlet />
      </main>

      <ConfirmDialog
        open={confirmLogout}
        danger
        busy={loggingOut}
        title="Точно хотите выйти?"
        description={
          <>
            Доступ GitHub будет отозван, а подключённые репозитории — отвязаны.
            Отчёты о сканированиях сохранятся: они снова появятся, когда вы войдёте под этим же аккаунтом.
          </>
        }
        confirmLabel={loggingOut ? 'Выходим...' : 'Выйти'}
        cancelLabel="Остаться"
        onCancel={() => setConfirmLogout(false)}
        onConfirm={handleLogout}
      />
    </div>
  );
};

const NavItem = ({ to, icon, label }: { to: string, icon: React.ReactNode, label: string }) => {
  return (
    <NavLink 
      to={to} 
      style={({ isActive }) => ({
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        padding: '0.75rem 1rem',
        borderRadius: 'var(--radius-sm)',
        textDecoration: 'none',
        color: isActive ? 'white' : 'var(--text-muted)',
        background: isActive ? 'var(--bg-surface-hover)' : 'transparent',
        borderLeft: isActive ? '3px solid var(--primary)' : '3px solid transparent',
        transition: 'all 0.2s',
        fontWeight: isActive ? 600 : 500
      })}
    >
      {icon}
      <span>{label}</span>
    </NavLink>
  );
}

export default Layout;
