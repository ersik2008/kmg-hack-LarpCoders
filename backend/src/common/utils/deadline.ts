/**
 * Ограничение времени асинхронной операции.
 *
 * ТЗ п. 4.7: шаг проверки укладывается в 30 минут и при превышении лимита
 * завершается корректно. Самый непредсказуемый по времени этап — AI-анализ:
 * при исчерпании лимита токенов Groq ключ уходит в паузу до 300 секунд, и таких
 * пауз может быть несколько подряд. Этап не должен тянуть за собой весь шаг.
 *
 * `Promise.race` не отменяет саму операцию — она может дорабатывать в фоне, но
 * результат уже не ожидается, а вердикт по требованиям ИБ от неё не зависит.
 */
export class DeadlineExceededError extends Error {
  constructor(readonly label: string, readonly ms: number) {
    super(`${label}: превышен бюджет времени ${Math.round(ms / 1000)} с`);
    this.name = 'DeadlineExceededError';
  }
}

export async function withDeadline<T>(operation: Promise<T>, ms: number, label: string): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) return operation;

  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new DeadlineExceededError(label, ms)), ms);
  });

  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
    // Если операция позже завершится ошибкой, это не должно стать unhandled rejection.
    operation.catch(() => undefined);
  }
}
