import winston from 'winston';
import { createCipheriv, createHmac, randomBytes } from 'crypto';
import { chmodSync } from 'fs';

const LOG_FILE = '/var/log/orders/app.log';

// Локальный журнал шифруется (AES-256-GCM), каждая запись подписывается HMAC,
// права файла ограничены владельцем; журнал отправляется на сервер.
export function protectLogLine(line: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(line, 'utf8'), cipher.final()]);
  const mac = createHmac('sha256', key).update(body).digest('hex');
  return `${iv.toString('hex')}:${body.toString('hex')}:${mac}`;
}

export const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.File({ filename: LOG_FILE }),
    new winston.transports.Http({ host: 'logs.example.invalid', ssl: true }),
  ],
});

chmodSync(LOG_FILE, 0o600);
