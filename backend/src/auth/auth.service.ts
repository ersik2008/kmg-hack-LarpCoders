import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/index.js';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  private get encryptionKey(): Buffer {
    const key = this.configService.get<string>('ENCRYPTION_KEY');
    if (!key || key.length !== 32) {
      throw new Error('ENCRYPTION_KEY must be exactly 32 characters long');
    }
    return Buffer.from(key);
  }

  private encrypt(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  }

  private decrypt(text: string): string {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift()!, 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }

  async validateOAuthUser(profile: any, accessToken: string) {
    const { id, username, emails, photos } = profile;
    const email = emails && emails.length > 0 ? emails[0].value : null;
    const githubId = parseInt(id, 10);
    if (!Number.isInteger(githubId)) {
      throw new Error(`GitHub profile did not contain a usable numeric id (got '${id}')`);
    }

    const encryptedToken = this.encrypt(accessToken);
    const avatarUrl = photos && photos.length > 0 ? photos[0].value : null;

    let githubAccount = await this.prisma.gitHubAccount.findUnique({
      where: { githubId },
      include: { user: true },
    });

    if (githubAccount) {
      // Update token
      githubAccount = await this.prisma.gitHubAccount.update({
        where: { id: githubAccount.id },
        data: { accessTokenHash: encryptedToken, avatarUrl },
        include: { user: true },
      });
      return githubAccount.user;
    }

    // No account for this GitHub id yet. The user row may still exist — GitHub
    // can deliver the callback more than once, and `email` is unique — so link
    // to the existing user instead of blindly creating a second one (which
    // failed with a 500 on `users_email_key`).
    if (email) {
      const existingUser = await this.prisma.user.findUnique({
        where: { email },
        include: { githubAccount: true },
      });

      if (existingUser) {
        await this.prisma.gitHubAccount.upsert({
          where: { userId: existingUser.id },
          create: {
            githubId,
            login: username,
            accessTokenHash: encryptedToken,
            avatarUrl,
            userId: existingUser.id,
          },
          update: {
            githubId,
            login: username,
            accessTokenHash: encryptedToken,
            avatarUrl,
          },
        });

        const refreshed = await this.prisma.user.update({
          where: { id: existingUser.id },
          data: { name: username, avatarUrl },
        });

        this.logger.log(`Linked GitHub account ${username} (${githubId}) to existing user ${existingUser.id}`);
        return refreshed;
      }
    }

    // Create new user and github account
    const newUser = await this.prisma.user.create({
      data: {
        email,
        name: username,
        avatarUrl,
        githubAccount: {
          create: {
            githubId,
            login: username,
            accessTokenHash: encryptedToken,
            avatarUrl,
          },
        },
      },
    });

    this.logger.log(`Created user ${newUser.id} for GitHub account ${username} (${githubId})`);
    return newUser;
  }

  /**
   * Fingerprint of the currently stored GitHub credential.
   *
   * It is embedded in the JWT and re-checked on every request, so a token stops
   * working as soon as the credential changes — on logout (cleared) and on a
   * new login (freshly encrypted value). Without it, a JWT captured before a
   * logout would start working again after the next sign-in.
   */
  static sessionFingerprint(accessTokenHash: string | null | undefined): string {
    return crypto
      .createHash('sha256')
      .update(accessTokenHash || '')
      .digest('hex')
      .slice(0, 32);
  }

  async login(user: any) {
    const githubAccount = await this.prisma.gitHubAccount.findUnique({
      where: { userId: user.id },
    });

    const payload = {
      sub: user.id,
      email: user.email,
      sid: AuthService.sessionFingerprint(githubAccount?.accessTokenHash),
    };

    return {
      accessToken: this.jwtService.sign(payload),
    };
  }

  /**
   * Full logout.
   *
   * The application has no session table: a JWT is accepted as long as the user
   * still has a usable GitHub access token (see JwtStrategy). Logout therefore:
   *   1. revokes the OAuth access token on GitHub's side (real server-side logout),
   *   2. optionally revokes the whole OAuth grant so the next login goes through
   *      the normal GitHub authorization flow instead of reusing the old grant,
   *   3. wipes the stored token, which immediately invalidates every JWT that was
   *      issued for this user,
   *   4. отвязывает репозитории: список в интерфейсе строится по этой связи, и
   *      после выхода он не должен показывать чужие репозитории. История
   *      сканов сохраняется — при повторном входе отчёты остаются на месте.
   */
  async logout(userId: string) {
    const githubAccount = await this.prisma.gitHubAccount.findUnique({
      where: { userId },
    });

    const revocation = {
      tokenRevoked: false,
      grantRevoked: false,
      error: null as string | null,
    };

    if (githubAccount?.accessTokenHash) {
      let accessToken: string | null = null;
      try {
        accessToken = this.decrypt(githubAccount.accessTokenHash);
      } catch (err: any) {
        revocation.error = `Stored GitHub token could not be decrypted: ${err.message}`;
        this.logger.warn(revocation.error);
      }

      if (accessToken) {
        const result = await this.revokeGithubAuthorization(accessToken);
        revocation.tokenRevoked = result.tokenRevoked;
        revocation.grantRevoked = result.grantRevoked;
        revocation.error = result.error ?? revocation.error;
      }

      // Local session/token teardown happens regardless of GitHub's answer:
      // an unreachable GitHub must never leave the user logged in locally.
      await this.prisma.gitHubAccount.update({
        where: { id: githubAccount.id },
        data: { accessTokenHash: '' },
      });
    }

    // Привязка к репозиториям снимается всегда, даже если GitHub-аккаунта в
    // базе уже нет: связь определяет видимость списка репозиториев.
    const { count } = await this.prisma.userRepository.deleteMany({ where: { userId } });

    this.logger.log(
      `User ${userId} logged out (github token revoked: ${revocation.tokenRevoked}, ` +
        `grant revoked: ${revocation.grantRevoked}, repository links removed: ${count})`,
    );

    return {
      success: true,
      ...revocation,
    };
  }

  /**
   * Calls the GitHub OAuth application API to invalidate the token / grant.
   * Requires HTTP Basic auth with the OAuth app credentials.
   */
  private async revokeGithubAuthorization(accessToken: string) {
    const clientId = this.configService.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GITHUB_CLIENT_SECRET');

    const result = { tokenRevoked: false, grantRevoked: false, error: null as string | null };

    if (!clientId || !clientSecret) {
      result.error = 'GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not configured, token cannot be revoked on GitHub';
      this.logger.warn(result.error);
      return result;
    }

    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const headers = {
      Authorization: `Basic ${basic}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    };

    // Revoking the grant also revokes every token issued under it and forces the
    // GitHub authorization screen on the next login. Enabled by default; set
    // GITHUB_REVOKE_GRANT_ON_LOGOUT=false to only drop the current token.
    const revokeGrant =
      (this.configService.get<string>('GITHUB_REVOKE_GRANT_ON_LOGOUT') ?? 'true').toLowerCase() !== 'false';

    const call = async (endpoint: 'token' | 'grant') => {
      const res = await fetch(`https://api.github.com/applications/${clientId}/${endpoint}`, {
        method: 'DELETE',
        headers,
        body: JSON.stringify({ access_token: accessToken }),
        signal: AbortSignal.timeout(10000),
      });
      // 204 = revoked, 404 = already unknown to GitHub (treated as revoked)
      if (res.status === 204 || res.status === 404) return true;
      throw new Error(`GitHub returned ${res.status} ${res.statusText}`);
    };

    try {
      result.tokenRevoked = await call('token');
    } catch (err: any) {
      result.error = `GitHub token revocation failed: ${err.message}`;
      this.logger.warn(result.error);
    }

    if (revokeGrant) {
      try {
        result.grantRevoked = await call('grant');
      } catch (err: any) {
        // Not fatal: the token itself is already revoked/cleared.
        const msg = `GitHub grant revocation failed: ${err.message}`;
        result.error = result.error ? `${result.error}; ${msg}` : msg;
        this.logger.warn(msg);
      }
    }

    return result;
  }
}
