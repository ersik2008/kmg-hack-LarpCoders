import { ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * GitHub OAuth guard that never throws.
 *
 * The default guard turns any OAuth failure — an expired or replayed code, a
 * GitHub hiccup, a profile fetch error — into an unhandled exception, which the
 * browser showed as a raw JSON 500 on /api/auth/github/callback. Swallowing the
 * error here lets the controller redirect back to the login screen with a
 * readable message instead.
 */
@Injectable()
export class GithubAuthGuard extends AuthGuard('github') {
  private readonly logger = new Logger(GithubAuthGuard.name);

  /**
   * passport-oauth2 wraps the actual GitHub response inside `err.oauthError`
   * (statusCode + body). `err.message` alone is always the generic "Failed
   * to obtain access token" — without this, a redirect_uri mismatch, a
   * revoked client secret, and a reused `code` are indistinguishable in logs.
   */
  private describe(err: any): string {
    const inner = err?.oauthError;
    if (inner?.statusCode || inner?.data) {
      return `${err.message} (HTTP ${inner.statusCode}: ${inner.data})`;
    }
    return err?.message || String(err);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      await super.canActivate(context);
    } catch (err: any) {
      this.logger.error(`GitHub OAuth failed: ${this.describe(err)}`);
    }
    // Always continue: the controller checks req.user and reacts accordingly.
    return true;
  }

  handleRequest(err: any, user: any): any {
    if (err) {
      this.logger.error(`GitHub OAuth callback error: ${this.describe(err)}`);
      return null;
    }
    return user || null;
  }
}
