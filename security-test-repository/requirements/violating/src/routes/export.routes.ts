import { Router } from 'express';
import { createObjectCsvWriter } from 'csv-writer';
import { db } from '../services/orders';

export const exportRouter = Router();

// Выгрузка пользователей: ни проверки роли администратора, ни записи аудита.
exportRouter.get('/export/users.csv', async (req, res) => {
  const users = await db.query('SELECT first_name, last_name, email FROM users');
  const writer = createObjectCsvWriter({
    path: '/tmp/users.csv',
    header: [{ id: 'email', title: 'Email' }],
  });
  await writer.writeRecords(users);
  res.download('/tmp/users.csv');
});
