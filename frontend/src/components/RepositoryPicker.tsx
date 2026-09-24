import { useEffect, useRef, useState } from 'react';
import { FolderGit2, Clock, ChevronDown, Check } from 'lucide-react';

/**
 * Выбор репозитория, по которому показывается страница.
 *
 * Страницы уязвимостей и цепочек атак работают с одним репозиторием за раз:
 * смешанный список по всем проектам не отвечает на вопрос «что сейчас не так
 * вот с этим». Выпадающий список вместо ряда карточек не растёт вширь, когда
 * репозиториев становится много.
 */

export interface ScannedRepository {
  id: string;
  name: string;
  fullName: string;
  lastScanId: string;
  lastScanAt: string;
}

export const formatScanDate = (iso: string): string =>
  new Date(iso).toLocaleString('ru-RU', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
  });

interface RepositoryPickerProps {
  repositories: ScannedRepository[];
  activeId: string | null;
  onChange: (id: string) => void;
  /** Ширина закрытого состояния; список подстраивается под неё. */
  width?: number;
}

const RepositoryPicker = ({ repositories, activeId, onChange, width = 300 }: RepositoryPickerProps) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Закрытие кликом вне списка и по Esc — как ожидается от дропдауна.
  useEffect(() => {
    if (!open) return;

    const onPointerDown = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };

    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  if (repositories.length === 0) return null;

  const active = repositories.find(r => r.id === activeId) || null;

  return (
    <div ref={ref} style={{ position: 'relative', width }}>
      <span
        style={{
          display: 'block', fontSize: '0.64rem', fontWeight: 600, color: 'var(--text-muted)',
          textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem',
        }}
      >
        Репозиторий
      </span>

      <button
        onClick={() => setOpen(v => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: '0.6rem',
          padding: '0.55rem 0.8rem', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
          background: 'var(--bg-surface)',
          border: `1px solid ${open ? 'var(--primary)' : 'var(--border-color)'}`,
          color: 'white', textAlign: 'left', transition: 'border-color 0.15s ease',
        }}
      >
        <FolderGit2 size={15} color="var(--primary)" style={{ flexShrink: 0 }} />

        <span style={{ flex: 1, minWidth: 0 }}>
          <span style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {active?.name || 'Выберите репозиторий'}
          </span>
          {active && (
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.28rem', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
              <Clock size={10} />
              скан {formatScanDate(active.lastScanAt)}
            </span>
          )}
        </span>

        <ChevronDown
          size={15}
          color="var(--text-muted)"
          style={{ flexShrink: 0, transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s ease' }}
        />
      </button>

      {open && (
        <div
          role="listbox"
          style={{
            position: 'absolute', top: 'calc(100% + 0.3rem)', left: 0, right: 0, zIndex: 30,
            background: 'var(--bg-surface)', border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-sm)', boxShadow: '0 16px 32px -12px rgba(0, 0, 0, 0.7)',
            overflow: 'hidden', maxHeight: '320px', overflowY: 'auto',
          }}
        >
          {repositories.map((repo, index) => {
            const isActive = activeId === repo.id;
            return (
              <button
                key={repo.id}
                role="option"
                aria-selected={isActive}
                onClick={() => {
                  onChange(repo.id);
                  setOpen(false);
                }}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: '0.6rem',
                  padding: '0.55rem 0.8rem', cursor: 'pointer', textAlign: 'left',
                  background: isActive ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
                  border: 'none',
                  borderLeft: `2px solid ${isActive ? 'var(--primary)' : 'transparent'}`,
                  color: isActive ? 'white' : 'var(--text-main)',
                }}
                onMouseEnter={e => {
                  if (!isActive) e.currentTarget.style.background = 'var(--bg-surface-hover)';
                }}
                onMouseLeave={e => {
                  if (!isActive) e.currentTarget.style.background = 'transparent';
                }}
              >
                <span style={{ flex: 1, minWidth: 0 }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.83rem', fontWeight: 600 }}>
                    <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{repo.name}</span>
                    {index === 0 && (
                      <span
                        style={{
                          flexShrink: 0, fontSize: '0.56rem', fontWeight: 600, padding: '0.05rem 0.35rem',
                          borderRadius: '999px', background: 'rgba(16, 185, 129, 0.15)',
                          border: '1px solid rgba(16, 185, 129, 0.3)', color: '#6ee7b7',
                          textTransform: 'uppercase', letterSpacing: '0.04em',
                        }}
                      >
                        последний
                      </span>
                    )}
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.28rem', fontSize: '0.66rem', color: 'var(--text-muted)' }}>
                    <Clock size={10} />
                    {formatScanDate(repo.lastScanAt)}
                  </span>
                </span>

                {isActive && <Check size={14} color="var(--primary)" style={{ flexShrink: 0 }} />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default RepositoryPicker;
