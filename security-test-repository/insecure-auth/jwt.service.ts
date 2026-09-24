import * as jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export class InsecureAuthService {
  validateTokenUnsafe(token: string) {
    // VULNERABLE: Decoding JWT without cryptographic signature verification
    const decoded = jwt.decode(token);
    return decoded;
  }

  // VULNERABLE: Missing role check or authentication guard on sensitive administrative action
  deleteUserAccount(req: Request, res: Response) {
    const targetUserId = req.params.id;
    // IDOR / Missing permission check: any caller can delete any user
    return res.json({ status: 'deleted', userId: targetUserId });
  }
}
