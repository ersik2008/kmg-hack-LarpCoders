import { useEffect, useRef } from 'react';

/**
 * Подписка на поток событий сканирования (SSE).
 *
 * Без неё страница узнавала о завершённом скане только по кнопке «Обновить»
 * или на следующем опросе, поэтому прогресс выглядел застывшим. Канал один на
 * вкладку и переподключается браузером самостоятельно.
 */

export interface ScanEvent {
  type: 'scan.completed' | 'scan.progress' | 'repositories.synced' | 'ping';
  scanId?: string;
  repositoryId?: string;
  payload?: {
    status?: string;
    verdict?: string | null;
    blocked?: boolean;
    riskScore?: number | null;
    repository?: string | null;
    branch?: string | null;
  };
}

const API = 'http://localhost:3000/api';

export const useScanEvents = (onEvent: (event: ScanEvent) => void) => {
  // Обработчик держим в ref: иначе каждое его пересоздание рвало бы
  // SSE-соединение и начинало новое.
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    const token = localStorage.getItem('kmg_token');
    if (!token) return;

    const source = new EventSource(`${API}/events/stream?token=${encodeURIComponent(token)}`);

    source.onmessage = event => {
      let data: ScanEvent;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }
      if (data?.type && data.type !== 'ping') handlerRef.current(data);
    };

    // Браузер переподключается сам; гасим только шум в консоли.
    source.onerror = () => {};

    return () => source.close();
  }, []);
};
