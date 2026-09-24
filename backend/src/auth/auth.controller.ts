import { Controller, Get, Post, Req, Res, UseGuards, Logger } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { GithubAuthGuard } from './guards/github-auth.guard.js';
import { GithubLoginGuard } from './guards/github-login.guard.js';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  private get frontendUrl(): string {
    return this.configService.get<string>('FRONTEND_URL', 'http://localhost:5173');
  }

  private loginError(res: Response, message: string) {
    return res.redirect(`${this.frontendUrl}/login?error=${encodeURIComponent(message)}`);
  }

  /** Старт OAuth. `?switch=1` — с выбором аккаунта на стороне GitHub. */
  @Get('github')
  @UseGuards(GithubLoginGuard)
  async githubAuth() {
    // Redirects to github
  }

  /**
   * OAuth failures here used to surface as a raw JSON 500 in the browser.
   * GithubAuthGuard never throws, so every outcome ends on the login screen
   * with a message the user can act on.
   */
  @Get('github/callback')
  @UseGuards(GithubAuthGuard)
  async githubAuthCallback(@Req() req: Request, @Res() res: Response) {
    if (!req.user) {
      return this.loginError(res, 'Не удалось завершить вход через GitHub. Попробуйте ещё раз.');
    }

    try {
      const { accessToken } = await this.authService.login(req.user as any);
      return res.redirect(`${this.frontendUrl}?token=${accessToken}`);
    } catch (err: any) {
      this.logger.error(`Failed to issue session after GitHub login: ${err?.message || err}`);
      return this.loginError(res, 'Вход выполнен, но создать сессию не удалось. Попробуйте ещё раз.');
    }
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getProfile(@Req() req: Request) {
    return req.user;
  }

  /**
   * Real logout: revokes the GitHub OAuth token/grant and wipes the stored
   * credentials, which invalidates every JWT issued for this user.
   */
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: Request) {
    const user = req.user as { id: string };
    return this.authService.logout(user.id);
  }
}
