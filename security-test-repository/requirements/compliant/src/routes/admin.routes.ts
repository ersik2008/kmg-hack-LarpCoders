import { Router } from 'express';
import { requireAdmin } from '../auth/auth.middleware';
import { db } from '../db/client';

export const adminRouter = Router();

// Все административные маршруты закрыты серверной проверкой роли.
adminRouter.use(requireAdmin);

adminRouter.get('/admin/users', async (req, res) => {
  res.json(await db.query('SELECT id, email FROM users'));
});
