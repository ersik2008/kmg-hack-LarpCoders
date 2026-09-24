import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
}

@Injectable()
export class CleanUserService {
  constructor(private readonly db: any) {}

  /**
   * Secure parameterized query prevents SQL injection
   */
  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const query = 'SELECT id, email, password_hash FROM users WHERE email = $1 LIMIT 1';
    const result = await this.db.query(query, [email]);
    return result.rows[0] || null;
  }

  /**
   * Secure password hashing using PBKDF2 with unique salt
   */
  hashPasswordSecure(password: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, 310000, 32, 'sha256', (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey.toString('hex'));
      });
    });
  }
}
