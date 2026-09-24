import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

const PUBLIC = /^\/(health|login|auth)/;

// Серверная проверка токена при каждом обращении к защищённым маршрутам.
export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  if (PUBLIC.test(req.path)) return next();
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    (req as any).user = jwt.verify(token, process.env.JWT_SECRET as string, { algorithms: ['HS256'] });
    next();
  } catch {
    res.sendStatus(401);
  }
}

export function issueToken(userId: string, role: string): string {
  return jwt.sign({ sub: userId, role }, process.env.JWT_SECRET as string, { expiresIn: '15m' });
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if ((req as any).user?.role !== 'admin') return res.sendStatus(403);
  next();
}
