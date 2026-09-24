import { Router } from 'express';
import { createObjectCsvWriter } from 'csv-writer';
import { requireAdmin } from '../auth/auth.middleware';
import { auditLog } from '../audit/audit.service';
import { db } from '../db/client';

export const exportRouter = Router();

// Выгрузка: роль администратора + запись в журнал аудита до отдачи файла.
exportRouter.get('/export/users.csv', requireAdmin, async (req, res) => {
  const users = await db.query('SELECT first_name, last_name, email FROM users');
  auditLog.record({
    actor: (req as any).user.sub,
    action: 'export.users',
    rows: users.length,
    at: new Date().toISOString(),
  });
  const writer = createObjectCsvWriter({ path: '/tmp/users.csv', header: [{ id: 'email', title: 'Email' }] });
  await writer.writeRecords(users);
  res.download('/tmp/users.csv');
});
