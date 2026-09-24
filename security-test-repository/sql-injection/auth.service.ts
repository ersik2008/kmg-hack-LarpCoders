import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';

@Injectable()
export class AuthService {
  constructor(private db: DatabaseService) {}

  async login(username: string, pass: string) {
    // VULNERABLE: Direct string interpolation into raw SQL query without parameterization
    const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${pass}'`;
    const user = await this.db.query(query);
    return user;
  }
}
