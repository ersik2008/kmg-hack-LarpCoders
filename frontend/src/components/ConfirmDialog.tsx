import React, { useEffect, useRef } from 'react';
import { AlertTriangle } from 'lucide-react';

/**
 * Модальное подтверждение для действий, которые нельзя отменить одним кликом.
 *
 * Закрывается по Esc и по клику вне окна, фокус уводится на «Отмену»: случайно
 * подтвердить действие с клавиатуры не должно получаться.
 */

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Красная кнопка подтверждения — для выхода, удаления и подобного. */
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

const ConfirmDialog = ({
  open,
  title,
  description,
  confirmLabel = 'Подтвердить',
  cancelLabel = 'Отмена',
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) => {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) onCancel();
    };

    document.addEventListener('keydown', onKeyDown);
    cancelRef.current?.focus();

    // Фон не должен прокручиваться, пока открыто окно.
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, busy, onCancel]);

  if (!open) return null;

  return (
    <div
      className="confirm-overlay"
      onClick={() => !busy && onCancel()}
      role="presentation"
    >
      <div
        className="confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        // Клик внутри окна не должен закрывать его через оверлей.
        onClick={event => event.stopPropagation()}
      >
        <div className="confirm-dialog-head">
          <div className={`confirm-dialog-icon${danger ? ' is-danger' : ''}`}>
            <AlertTriangle size={20} />
          </div>
          <h3 id="confirm-dialog-title" className="confirm-dialog-title">
            {title}
          </h3>
        </div>

        {description && <div className="confirm-dialog-text">{description}</div>}

        <div className="confirm-dialog-actions">
          <button
            ref={cancelRef}
            type="button"
            className="confirm-btn confirm-btn-cancel"
            onClick={onCancel}
            disabled={busy}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            className={`confirm-btn${danger ? ' confirm-btn-danger' : ' confirm-btn-primary'}`}
            onClick={onConfirm}
            disabled={busy}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmDialog;
