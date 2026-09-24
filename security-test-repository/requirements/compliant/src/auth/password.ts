import argon2 from 'argon2';

// Пароль хранится в виде значения адаптивной функции формирования ключа.
export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, { type: argon2.argon2id });
}

export function verifyPassword(password: string, stored: string): Promise<boolean> {
  return argon2.verify(stored, password);
}
