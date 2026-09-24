import React, { useEffect, useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderGit2, ShieldAlert, Settings, LogOut, GitFork, User as UserIcon } from 'lucide-react';
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
      <aside className="sidebar">
        {/* Logo */}
        <div className="sidebar-logo">
          <img src="/favicon.svg" alt="KMG Digital" className="sidebar-logo-icon" />
          <div className="sidebar-logo-text">
            <span className="sidebar-logo-name">KMG</span>
            <span className="sidebar-logo-sub">DIGITAL</span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav">
          <NavItem to="/dashboard" icon={<LayoutDashboard size={18} strokeWidth={1.5} />} label="Обзор" />
          <NavItem to="/repositories" icon={<FolderGit2 size={18} strokeWidth={1.5} />} label="Репозитории" />
          <NavItem to="/attack-paths" icon={<GitFork size={18} strokeWidth={1.5} />} label="Цепочки атак" />
          <NavItem to="/findings" icon={<ShieldAlert size={18} strokeWidth={1.5} />} label="Все уязвимости" />
          <NavItem to="/settings" icon={<Settings size={18} strokeWidth={1.5} />} label="Настройки" />
        </nav>

        {/* User Profile & Logout */}
        <div className="sidebar-footer">
          <div className="sidebar-user">
            {avatar ? (
              <img
                src={avatar}
                alt={displayName}
                className="sidebar-avatar"
              />
            ) : (
              <div className="sidebar-avatar-placeholder">
                <UserIcon size={16} />
              </div>
            )}
            <div className="sidebar-user-info">
              <div className="sidebar-user-name">{displayName}</div>
              <div className="sidebar-user-login">{displayLogin}</div>
            </div>
          </div>

          <button
            onClick={() => setConfirmLogout(true)}
            disabled={loggingOut}
            className="sidebar-logout-btn"
          >
            <LogOut size={15} strokeWidth={1.5} />
            {loggingOut ? 'Выход...' : 'Выйти'}
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
      className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`}
    >
      <span className="sidebar-nav-icon">{icon}</span>
      <span>{label}</span>
    </NavLink>
  );
}

export default Layout;
