import { Router } from 'express';
import { db } from '../db/client';

export const ordersRouter = Router();

ordersRouter.get('/orders', async (req, res) => {
  res.json(await db.query('SELECT * FROM orders'));
});

ordersRouter.post('/orders', async (req, res) => {
  await db.query('INSERT INTO orders (title) VALUES ($1)', [req.body.title]);
  res.sendStatus(201);
});
