import { Request, Response, NextFunction } from 'express';
import { auditLog } from './audit.service';

// Единый механизм журналирования действий пользователей: регистрируется один
// раз и охватывает все обработчики приложения.
export function auditMiddleware(req: Request, res: Response, next: NextFunction) {
  res.on('finish', () => {
    auditLog.record({
      actor: (req as any).user?.sub ?? 'anonymous',
      action: `${req.method} ${req.path}`,
      status: res.statusCode,
      at: new Date().toISOString(),
    });
  });
  next();
}
