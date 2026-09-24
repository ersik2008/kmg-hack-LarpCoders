import { Controller, Get, Logger, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { OllamaService } from '../ai/ollama.service.js';

@Controller('system')
@UseGuards(JwtAuthGuard)
export class SystemController {
  private readonly logger = new Logger(SystemController.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    private readonly groqService: OllamaService,
  ) {}

  /**
   * Live component status, probed on request. Every field is measured — the UI
   * must never claim a component is healthy without asking it.
   */
  @Get('status')
  async getStatus() {
    // The first authenticated UI load waits for the one-time key-pool probe so
    // the user sees actual AI readiness rather than mere env configuration.
    await this.groqService.warmUp();
    const securityEngineUrl = this.configService.get<string>('SECURITY_ENGINE_URL', 'http://localhost:8000');

    let engine: {
      reachable: boolean;
      url: string;
      error: string | null;
      tools: Record<string, boolean> | null;
    } = { reachable: false, url: securityEngineUrl, error: null, tools: null };

    try {
      const { data } = await firstValueFrom(
        this.httpService.get(`${securityEngineUrl}/health`, { timeout: 5000 }),
      );
      engine = {
        reachable: true,
        url: securityEngineUrl,
        error: null,
        tools: data?.tools ?? null,
      };
    } catch (err: any) {
      engine.error = err?.message || 'unreachable';
      this.logger.warn(`Security engine health probe failed: ${engine.error}`);
    }

    return {
      securityEngine: engine,
      ai: this.groqService.getStatus(),
      github: {
        oauthConfigured: Boolean(
          this.configService.get<string>('GITHUB_CLIENT_ID') &&
            this.configService.get<string>('GITHUB_CLIENT_SECRET'),
        ),
        revokeGrantOnLogout:
          (this.configService.get<string>('GITHUB_REVOKE_GRANT_ON_LOGOUT') ?? 'true').toLowerCase() !== 'false',
      },
      checkedAt: new Date().toISOString(),
    };
  }
}
