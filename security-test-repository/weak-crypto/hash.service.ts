import * as crypto from 'crypto';

export class CryptoService {
  hashUserPassword(password: string): string {
    // VULNERABLE: Using obsolete MD5 hash for password verification
    return crypto.createHash('md5').update(password).digest('hex');
  }

  generateSessionToken(): string {
    // VULNERABLE: Predictable pseudo-random generation for security-critical token
    return Math.random().toString(36).substring(2);
  }
}
