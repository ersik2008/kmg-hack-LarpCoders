import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-github2';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service.js';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  private readonly logger = new Logger(GithubStrategy.name);

  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    const clientID = configService.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = configService.get<string>('GITHUB_CLIENT_SECRET');

    // Starting with placeholder credentials only produces a confusing GitHub
    // error page later; refuse to boot instead.
    if (!clientID || !clientSecret) {
      throw new Error(
        'GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be configured — GitHub OAuth cannot start without real credentials.',
      );
    }

    super({
      clientID,
      clientSecret,
      callbackURL: configService.get<string>('GITHUB_CALLBACK_URL') || 'http://localhost:3000/api/auth/github/callback',
      // security_events нужен, чтобы выгружать SARIF в GitHub Code Scanning.
      // Аккаунты, авторизованные до добавления этого права, получат 403 на
      // выгрузке, пока пользователь не войдёт заново.
      scope: ['user:email', 'repo', 'read:org', 'security_events'],
    });

    this.patchTokenExchange();
  }

  /**
   * DNS/socket blips (`EAI_AGAIN`, `ECONNRESET`, ...) reach us here as a hard
   * OAuth failure and bounce the user back to /login with a generic message,
   * even though a retry a second later succeeds — seen live: `getaddrinfo
   * EAI_AGAIN github.com` on an otherwise healthy container. `GithubService`
   * already retries the same class of errors for API calls; the token
   * exchange gets no such protection from passport-oauth2, so it's added here.
   */
  private static readonly TRANSIENT_CODES = ['EAI_AGAIN', 'ENOTFOUND', 'ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'EPIPE'];
  private static readonly MAX_ATTEMPTS = 3;

  /**
   * Wraps the OAuth2 client's token exchange to (1) retry transient network
   * errors and (2) log GitHub's raw response when no token comes back. The
   * `oauth` library only surfaces a network/HTTP-layer error through
   * `err.oauthError` — when GitHub answers 200 with a JSON body like
   * `{"error":"bad_verification_code"}`, it treats that as success and hands
   * back `access_token: undefined`, so the reason must be logged explicitly.
   */
  private patchTokenExchange(): void {
    const oauth2: any = (this as any)._oauth2;
    const original = oauth2.getOAuthAccessToken.bind(oauth2);

    const attempt = (code: string, params: any, tryNumber: number, callback: any) => {
      original(code, params, (err: any, accessToken: string, refreshToken: string, results: any) => {
        const isTransient = GithubStrategy.TRANSIENT_CODES.includes(err?.code);

        if (isTransient && tryNumber < GithubStrategy.MAX_ATTEMPTS) {
          this.logger.warn(`Token exchange: transient error ${err.code}, retry ${tryNumber}/${GithubStrategy.MAX_ATTEMPTS}`);
          setTimeout(() => attempt(code, params, tryNumber + 1, callback), 700 * tryNumber);
          return;
        }

        if (err) {
          this.logger.error(`Token exchange transport error: ${err?.message || err}`);
        } else if (!accessToken) {
          this.logger.error(`GitHub returned no access_token. Raw response: ${JSON.stringify(results)}`);
        }

        callback(err, accessToken, refreshToken, results);
      });
    };

    oauth2.getOAuthAccessToken = (code: string, params: any, callback: any) => attempt(code, params, 1, callback);
  }

  /**
   * passport-oauth2 по умолчанию выбрасывает любые дополнительные опции и в
   * GitHub их не передаёт. Пробрасываем `prompt`: со значением select_account
   * GitHub показывает выбор аккаунта, иначе вход молча идёт под тем, кто уже
   * залогинен в браузере, и сменить аккаунт невозможно.
   */
  authorizationParams(options: any): object {
    const params: Record<string, string> = {};
    if (options?.prompt) params.prompt = options.prompt;
    if (options?.login) params.login = options.login;
    return params;
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    return this.authService.validateOAuthUser(profile, accessToken);
  }
}
