import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/index.js';
import { AuthService } from '../auth.service.js';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET') || 'default_secret',
    });
  }

  async validate(payload: any) {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: { githubAccount: true },
    });
    
    if (!user) {
      throw new UnauthorizedException();
    }

    // Server-side session check. Logout wipes the stored GitHub access token,
    // so any JWT issued before that point is rejected here even though it is
    // still cryptographically valid and unexpired.
    if (!user.githubAccount || !user.githubAccount.accessTokenHash) {
      throw new UnauthorizedException('Session revoked. Please sign in with GitHub again.');
    }

    // The token must match the GitHub credential it was issued for, so tokens
    // from a previous session stay dead even after the user signs in again.
    const expectedSid = AuthService.sessionFingerprint(user.githubAccount.accessTokenHash);
    if (payload.sid !== expectedSid) {
      throw new UnauthorizedException('Session is no longer valid. Please sign in with GitHub again.');
    }

    return user;
  }
}
