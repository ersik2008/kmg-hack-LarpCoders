import express from 'express';
import https from 'https';
import helmet from 'helmet';
import { readFileSync } from 'fs';
import { authMiddleware } from './auth/auth.middleware';
import { auditMiddleware } from './audit/audit.middleware';
import { adminRouter } from './routes/admin.routes';
import { exportRouter } from './routes/export.routes';
import { ordersRouter } from './routes/orders.routes';

const app = express();
app.use(express.json());
app.use(helmet({ hsts: { maxAge: 31536000 } }));

// Единые механизмы, применённые ко всему приложению.
app.use(authMiddleware);
app.use(auditMiddleware);

app.use('/admin', adminRouter);
app.use('/export', exportRouter);
app.use('/orders', ordersRouter);

https
  .createServer({ key: readFileSync('/etc/tls/key.pem'), cert: readFileSync('/etc/tls/cert.pem'), minVersion: 'TLSv1.2' }, app)
  .listen(3443);
