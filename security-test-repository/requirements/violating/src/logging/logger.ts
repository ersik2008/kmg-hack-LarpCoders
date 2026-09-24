import winston from 'winston';

// Локальный журнал пишется в файл открытым текстом, без шифрования и защиты
// от модификации.
export const logger = winston.createLogger({
  level: 'info',
  transports: [new winston.transports.File({ filename: '/var/log/orders/app.log' })],
});
