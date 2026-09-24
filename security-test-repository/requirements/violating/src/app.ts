import express from 'express';
import http from 'http';
import { adminRouter } from './routes/admin.routes';
import { exportRouter } from './routes/export.routes';
import { ordersRouter } from './services/orders';

const app = express();
app.use(express.json());

// Маршруты подключаются без какой-либо аутентификации.
app.use('/admin', adminRouter);
app.use('/export', exportRouter);
app.use('/orders', ordersRouter);

// Сервер обслуживает обычный HTTP, TLS не настроен.
http.createServer(app).listen(3000);
