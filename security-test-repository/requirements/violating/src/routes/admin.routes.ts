import { Router } from 'express';
import { db } from '../services/orders';

export const adminRouter = Router();

// Административные маршруты без серверной проверки роли.
adminRouter.get('/admin/users', async (req, res) => {
  res.json(await db.query('SELECT id, email FROM users'));
});

adminRouter.delete('/admin/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ' + req.params.id);
  res.sendStatus(204);
});
