import { createHash } from 'crypto';

// Пароль хешируется быстрой хеш-функцией общего назначения без адаптивного KDF.
export function hashPassword(password: string): string {
  return createHash('sha256').update(password).digest('hex');
}

export function verifyPassword(password: string, stored: string): boolean {
  return hashPassword(password) === stored;
}
