import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Shield, ScanSearch, GitPullRequestArrow, Bot, AlertTriangle } from 'lucide-react';

/**
 * Фирменный значок GitHub (Octocat mark).
 *
 * lucide-react не включает брендовые логотипы, только обобщённые иконки
 * (GitBranch и т.п.) — официальный SVG-путь взят из github.com/logos и
 * встроен напрямую, без подключения react-icons ради одной иконки.
 */
const GithubMark = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
  </svg>
);

const Login = () => {
  const [searchParams] = useSearchParams();
  const [signingIn, setSigningIn] = useState(false);

  // The backend redirects here with ?error=... when the OAuth round-trip fails,
  // instead of leaving a raw API error in the browser.
  const error = searchParams.get('error');

  // Landing on /login always means "no session": drop any leftover token so a
  // stale one can never be picked up again by ProtectedRoute.
  useEffect(() => {
    try {
      localStorage.removeItem('kmg_token');
    } catch {
      /* storage unavailable — nothing to clear */
    }
  }, []);

  /**
   * Вход через GitHub всегда идёт с prompt=select_account: без него браузер
   * с уже выполненным входом на github.com молча возвращает того же
   * пользователя, и сменить аккаунт с этой кнопки было нельзя.
   */
  const handleLogin = () => {
    setSigningIn(true);
    window.location.href = 'http://localhost:3000/api/auth/github?switch=1';
  };

  return (
    <div className="login-screen">
      <div className="login-grid">
        {/* Left: what the product does */}
        <section className="login-pitch">
          <div className="login-brand">
            <div className="login-brand-mark">
              <Shield size={26} strokeWidth={2.2} />
            </div>
            <div>
              <div className="login-brand-name">KMG AI</div>
              <div className="login-brand-sub">Security Agent</div>
            </div>
          </div>

          <h1 className="login-title">
            Уязвимости — <span className="login-title-accent">до</span> того,
            <br />как они попадут в репозиторий
          </h1>

          <p className="login-lead">
            Платформа проверяет код на этапе <code>git push</code> и блокирует отправку,
            если найдены критические проблемы. Проверка выполняется до того, как код уйдёт в GitHub.
          </p>

          <ul className="login-features">
            <li>
              <span className="login-feature-icon"><ScanSearch size={18} /></span>
              <div>
                <strong>Реальные сканеры</strong>
                <span className="login-feature-text">Semgrep, Gitleaks и Trivy — поиск уязвимостей, секретов и уязвимых зависимостей</span>
              </div>
            </li>
            <li>
              <span className="login-feature-icon"><GitPullRequestArrow size={18} /></span>
              <div>
                <strong>Защита перед push</strong>
                <span className="login-feature-text">Git-хук прерывает отправку и показывает файл, строку и severity</span>
              </div>
            </li>
            <li>
              <span className="login-feature-icon"><Bot size={18} /></span>
              <div>
                <strong>AI-разбор находок</strong>
                <span className="login-feature-text">Агент исследует код и объясняет, чем именно опасна каждая находка</span>
              </div>
            </li>
          </ul>
        </section>

        {/* Right: the actual sign-in */}
        <section className="login-card">
          <h2 className="login-card-title">Вход в систему</h2>
          <p className="login-card-sub">
            Авторизуйтесь через GitHub, чтобы подключить репозитории и запускать проверки.
          </p>

          {error && (
            <div className="login-error" role="alert">
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}

          <button
            onClick={handleLogin}
            disabled={signingIn}
            className="login-github-btn"
          >
            <GithubMark size={20} />
            {signingIn ? 'Переходим в GitHub...' : 'Войти через GitHub'}
          </button>

          <div className="login-scopes">
            <div className="login-scopes-title">Какие доступы запрашиваются</div>
            <ul>
              <li><code>repo</code> — чтение кода репозиториев для сканирования</li>
              <li><code>user:email</code> — адрес почты для вашей учётной записи</li>
              <li><code>read:org</code> — список репозиториев организаций</li>
            </ul>
          </div>

          <p className="login-note">
            Токен доступа хранится в зашифрованном виде и отзывается на стороне GitHub
            при выходе из аккаунта.
          </p>
        </section>
      </div>
    </div>
  );
};

export default Login;
