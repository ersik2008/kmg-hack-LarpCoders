import { Router } from 'express';

export const db = { query: async (sql: string): Promise<any[]> => [] };
export const ordersRouter = Router();

// Журналирование есть только здесь, в единственном обработчике, а единого
// механизма нет ни в других обработчиках, ни на уровне БД.
ordersRouter.get('/orders', async (req, res) => {
  console.log('orders listed');
  res.json(await db.query('SELECT * FROM orders'));
});

ordersRouter.post('/orders', async (req, res) => {
  await db.query('INSERT INTO orders (title) VALUES (' + req.body.title + ')');
  res.sendStatus(201);
});

ordersRouter.put('/orders/:id', async (req, res) => {
  await db.query('UPDATE orders SET title = ' + req.body.title + ' WHERE id = ' + req.params.id);
  res.sendStatus(200);
});
