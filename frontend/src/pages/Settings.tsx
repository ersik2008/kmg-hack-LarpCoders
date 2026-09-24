import React, { useCallback, useEffect, useState } from 'react';
import {
  Shield, Key, Save, Check, GitBranch, Copy, Activity,
  AlertTriangle, RefreshCw, Loader2,
} from 'lucide-react';

const API = 'http://localhost:3000/api';

interface PolicySettings {
  blockOnCritical: boolean;
  blockRiskScore: number;
  reviewRiskScore: number;
  reviewHighCount: number;
  scanners: { semgrep: boolean; gitleaks: boolean; trivy: boolean };
  aiAnalysis: boolean;
}

interface SystemStatus {
  securityEngine: {
    reachable: boolean;
    url: string;
    error: string | null;
    tools: Record<string, boolean> | null;
  };
  ai: {
    provider: string;
    configured: boolean;
    available: boolean;
    model: string | null;
    totalKeys: number;
    healthyKeys: number;
    coolingDownKeys: number;
    invalidKeys: number;
  };
  github: { oauthConfigured: boolean; revokeGrantOnLogout: boolean };
  checkedAt: string;
}

const authHeaders = (): HeadersInit => ({
  Authorization: `Bearer ${localStorage.getItem('kmg_token') || ''}`,
  'Content-Type': 'application/json',
});

const Settings = () => {
  const [policy, setPolicy] = useState<PolicySettings | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/system/status`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStatus(await res.json());
    } catch (err: any) {
      setStatus(null);
      setError(`Не удалось получить статус системы: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`${API}/policy`, { headers: authHeaders() });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setPolicy(await res.json());
      } catch (err: any) {
        setError(`Не удалось загрузить политику: ${err.message}`);
      }
      await loadStatus();
      setLoading(false);
    };
    load();
  }, [loadStatus]);

  const save = async () => {
    if (!policy) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`${API}/policy`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(policy),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // The server normalises and clamps values: adopt what it actually stored.
      setPolicy(await res.json());
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: any) {
      setError(`Не удалось сохранить: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const patch = (changes: Partial<PolicySettings>) =>
    setPolicy(prev => (prev ? { ...prev, ...changes } : prev));

  const patchScanner = (name: keyof PolicySettings['scanners'], value: boolean) =>
    setPolicy(prev => (prev ? { ...prev, scanners: { ...prev.scanners, [name]: value } } : prev));

  const noScanners = policy && !policy.scanners.semgrep && !policy.scanners.gitleaks && !policy.scanners.trivy;

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1>Настройки</h1>
        <p style={{ color: 'var(--text-muted)' }}>
          Эти значения применяются реально: ими управляется сканирование репозиториев и проверка до push.
        </p>
      </div>

      {error && (
        <div className="card" style={{ border: '1px solid var(--danger)', color: '#fca5a5', marginBottom: '1.5rem' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ color: 'var(--text-muted)', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <Loader2 size={18} /> Загрузка конфигурации...
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <SystemStatusCard status={status} onRefresh={loadStatus} />

          {policy && (
            <>
              <div className="card">
                <h3 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Shield size={20} /> Сканеры
                </h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '1.25rem' }}>
                  Отключённый сканер не запускается и помечается как <code>SKIPPED</code>. Его область
                  проверки не может быть зачтена как «уязвимостей нет».
                </p>

                {noScanners && (
                  <div style={{
                    display: 'flex', gap: '0.6rem', alignItems: 'center', marginBottom: '1rem',
                    padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)',
                    background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.35)',
                  }}>
                    <AlertTriangle size={18} color="#f87171" />
                    <span style={{ fontSize: '0.82rem', color: '#fca5a5' }}>
                      Все сканеры отключены — вердикт вынести невозможно, сканирование будет помечено
                      как незавершённое, а push будет блокироваться.
                    </span>
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <SettingRow
                    label="Semgrep"
                    description="Статический анализ кода (SAST)"
                    control={<ToggleSwitch checked={policy.scanners.semgrep} onChange={v => patchScanner('semgrep', v)} />}
                  />
                  <SettingRow
                    label="Gitleaks"
                    description="Поиск секретов и учётных данных"
                    control={<ToggleSwitch checked={policy.scanners.gitleaks} onChange={v => patchScanner('gitleaks', v)} />}
                  />
                  <SettingRow
                    label="Trivy"
                    description="Уязвимости зависимостей и ошибки конфигурации"
                    control={<ToggleSwitch checked={policy.scanners.trivy} onChange={v => patchScanner('trivy', v)} />}
                  />
                  <SettingRow
                    label="AI-анализ (Qwen)"
                    description={
                      status?.ai.configured
                        ? `Расследование агентом, модель ${status.ai.model || 'по умолчанию'}`
                        : 'OLLAMA_BASE_URL не настроен — анализ выполняться не будет'
                    }
                    control={
                      <ToggleSwitch
                        checked={policy.aiAnalysis && Boolean(status?.ai.configured)}
                        disabled={!status?.ai.configured}
                        onChange={v => patch({ aiAnalysis: v })}
                      />
                    }
                  />
                </div>
              </div>

              <div className="card">
                <h3 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Shield size={20} /> Пороги политики
                </h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '1.25rem' }}>
                  По этим значениям выносится вердикт BLOCK / REVIEW / PASS и блокируется push.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <SettingRow
                    label="Блокировать при CRITICAL"
                    description="Любая критическая находка даёт вердикт BLOCK"
                    control={<ToggleSwitch checked={policy.blockOnCritical} onChange={v => patch({ blockOnCritical: v })} />}
                  />
                  <SettingRow
                    label="Порог риска для BLOCK"
                    description="Оценка риска (0–10), начиная с которой выносится BLOCK"
                    control={<NumberInput value={policy.blockRiskScore} step={0.5} onChange={v => patch({ blockRiskScore: v })} />}
                  />
                  <SettingRow
                    label="Порог риска для REVIEW"
                    description="Оценка риска (0–10), начиная с которой нужна ручная проверка"
                    control={<NumberInput value={policy.reviewRiskScore} step={0.5} onChange={v => patch({ reviewRiskScore: v })} />}
                  />
                  <SettingRow
                    label="Количество HIGH для REVIEW"
                    description="Сколько находок HIGH допустимо до перехода в REVIEW"
                    control={<NumberInput value={policy.reviewHighCount} step={1} onChange={v => patch({ reviewHighCount: v })} />}
                  />
                </div>
              </div>

              <PrePushGuardCard />

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  className="btn btn-primary"
                  onClick={save}
                  disabled={saving}
                  style={{ display: 'flex', gap: '0.5rem', opacity: saving ? 0.6 : 1 }}
                >
                  {saved ? <Check size={18} /> : <Save size={18} />}
                  {saving ? 'Сохранение...' : saved ? 'Сохранено' : 'Сохранить'}
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

/** Live component health, probed by the backend on every refresh. */
const SystemStatusCard = ({ status, onRefresh }: { status: SystemStatus | null; onRefresh: () => void }) => {
  const [refreshing, setRefreshing] = useState(false);
  const [retrying, setRetrying] = useState(false);

  const refresh = async () => {
    setRefreshing(true);
    await onRefresh();
    setRefreshing(false);
  };

  const retryAi = async () => {
    setRetrying(true);
    try {
      await fetch(`${API}/system/ai/retry`, {
        method: 'POST',
        headers: authHeaders(),
      });
      await onRefresh();
    } catch {}
    setRetrying(false);
  };

  const tools = status?.securityEngine.tools;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Activity size={20} /> Состояние системы
        </h3>
        <button className="btn btn-outline" onClick={refresh} disabled={refreshing} style={{ fontSize: '0.8rem' }}>
          <RefreshCw size={14} style={{ marginRight: '0.4rem' }} />
          {refreshing ? 'Проверка...' : 'Проверить'}
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <StatusRow
          label="Security Engine"
          ok={Boolean(status?.securityEngine.reachable)}
          detail={status?.securityEngine.reachable
            ? status.securityEngine.url
            : status?.securityEngine.error || 'не проверялось'}
        />
        {(['semgrep', 'gitleaks', 'trivy'] as const).map(tool => (
          <StatusRow
            key={tool}
            label={`└ ${tool}`}
            ok={Boolean(tools?.[tool])}
            detail={tools ? (tools[tool] ? 'установлен' : 'НЕ НАЙДЕН в образе') : 'движок недоступен'}
          />
        ))}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <StatusRow
            label="AI (Qwen / Ollama)"
            ok={Boolean(status?.ai.available)}
            detail={status?.ai.configured
              ? (status.ai.available
                  ? (status.ai.model || 'qwen3') + ' · готов '
                  : 'недоступен — повторите подключение')
              : 'OLLAMA_BASE_URL не настроен'}
          />
          {status?.ai.configured && !status.ai.available && (
            <button
              className="btn btn-outline"
              onClick={retryAi}
              disabled={retrying}
              style={{ fontSize: '0.72rem', padding: '0.25rem 0.6rem', flexShrink: 0, whiteSpace: 'nowrap' }}
            >
              {retrying ? <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <RefreshCw size={13} />}
              {retrying ? 'Подключение...' : 'Повторить'}
            </button>
          )}
        </div>
        <StatusRow
          label="GitHub OAuth"
          ok={Boolean(status?.github.oauthConfigured)}
          detail={status?.github.oauthConfigured
            ? (status.github.revokeGrantOnLogout ? 'при выходе отзывается grant' : 'при выходе отзывается только токен')
            : 'GITHUB_CLIENT_ID / SECRET не заданы'}
        />
      </div>

      {status && (
        <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginTop: '1rem', marginBottom: 0 }}>
          Проверено: {new Date(status.checkedAt).toLocaleTimeString()}
        </p>
      )}
    </div>
  );
};

const StatusRow = ({ label, ok, detail }: { label: string; ok: boolean; detail: string }) => (
  <div style={{
    display: 'flex', alignItems: 'center', gap: '0.75rem',
    padding: '0.55rem 0.9rem', background: 'var(--bg-dark)', borderRadius: 'var(--radius-sm)',
  }}>
    <span style={{
      width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0,
      background: ok ? 'var(--accent)' : 'var(--danger)',
    }} />
    <span style={{ fontSize: '0.85rem', minWidth: '150px' }}>{label}</span>
    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>{detail}</span>
  </div>
);

/**
 * Setup panel for the git pre-push guard: the hook needs this session token to
 * call /api/prepush/check before git transfers anything to the remote.
 */
const PrePushGuardCard = () => {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const token = localStorage.getItem('kmg_token') || '';

  const copy = async (value: string, key: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable — the value is selectable on screen */
    }
  };

  const commands = [
    { key: 'install', text: './tools/git-hooks/install.sh /path/to/your/repo' },
    { key: 'token', text: `git -C /path/to/your/repo config --local kmg.token ${revealed ? token : '<ТОКЕН>'}` },
    { key: 'api', text: 'git -C /path/to/your/repo config --local kmg.apiurl http://localhost:3000/api' },
  ];

  return (
    <div className="card">
      <h3 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <GitBranch size={20} /> Проверка до push (pre-push guard)
      </h3>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
        Git-хук проверяет код <strong>до</strong> отправки в GitHub и прерывает push при критических
        уязвимостях. Установите его в репозиторий, с которым работаете:
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {commands.map(cmd => (
          <div
            key={cmd.key}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.75rem',
              background: 'var(--bg-dark)', border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)', padding: '0.6rem 0.9rem',
            }}
          >
            <code style={{ flex: 1, fontSize: '0.8rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
              {cmd.text}
            </code>
            <button
              className="btn btn-outline"
              onClick={() => copy(cmd.text, cmd.key)}
              style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', flexShrink: 0 }}
            >
              {copied === cmd.key ? <Check size={14} /> : <Copy size={14} />}
            </button>
          </div>
        ))}
      </div>

      <button
        className="btn btn-outline"
        onClick={() => setRevealed(v => !v)}
        style={{ marginTop: '1rem', fontSize: '0.8rem' }}
      >
        <Key size={14} style={{ marginRight: '0.4rem' }} />
        {revealed ? 'Скрыть токен' : 'Показать мой токен сессии'}
      </button>

      <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '1rem' }}>
        Токен привязан к текущей сессии: после выхода из аккаунта он перестаёт действовать,
        и хук нужно настроить заново с новым токеном.
      </p>
    </div>
  );
};

const SettingRow = ({ label, description, control }: { label: string; description: string; control: React.ReactNode }) => (
  <div style={{
    display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem',
    padding: '1rem', background: 'var(--bg-dark)', borderRadius: 'var(--radius-sm)',
  }}>
    <div>
      <h4 style={{ margin: 0, fontSize: '0.95rem' }}>{label}</h4>
      <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{description}</p>
    </div>
    {control}
  </div>
);

const NumberInput = ({ value, step, onChange }: { value: number; step: number; onChange: (v: number) => void }) => (
  <input
    type="number"
    value={value}
    step={step}
    min={0}
    max={10}
    onChange={e => onChange(Number(e.target.value))}
    style={{
      padding: '0.5rem 1rem', background: 'var(--bg-surface)',
      border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)',
      color: 'white', outline: 'none', width: '110px', textAlign: 'center',
    }}
  />
);

const ToggleSwitch = ({
  checked, onChange, disabled = false,
}: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) => (
  <div
    onClick={() => !disabled && onChange(!checked)}
    title={disabled ? 'Недоступно: компонент не настроен' : undefined}
    style={{
      width: '48px', height: '26px', borderRadius: '13px',
      cursor: disabled ? 'not-allowed' : 'pointer',
      background: checked ? 'var(--primary)' : 'var(--bg-surface-hover)',
      border: '1px solid var(--border-color)',
      position: 'relative', transition: 'background 0.2s',
      opacity: disabled ? 0.45 : 1, flexShrink: 0,
    }}
  >
    <div style={{
      width: '20px', height: '20px', borderRadius: '50%',
      background: 'white', position: 'absolute', top: '2px',
      left: checked ? '24px' : '2px',
      transition: 'left 0.2s',
    }} />
  </div>
);

export default Settings;
