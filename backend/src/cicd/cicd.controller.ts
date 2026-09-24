import { Controller, Post, Body, Headers, UnauthorizedException, Logger } from '@nestjs/common';
import { CicdService } from './cicd.service.js';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';

@Controller('cicd')
export class CicdController {
  private readonly logger = new Logger(CicdController.name);

  constructor(
    private readonly cicdService: CicdService,
    private readonly configService: ConfigService,
  ) {}

  @Post('webhook/github')
  async handleGithubWebhook(
    @Headers('x-hub-signature-256') signature: string,
    @Headers('x-github-event') event: string,
    @Body() payload: any,
  ) {
    // Verify webhook signature
    const secret = this.configService.get<string>('GITHUB_WEBHOOK_SECRET');
    if (secret) {
      const expectedSig = 'sha256=' + crypto
        .createHmac('sha256', secret)
        .update(JSON.stringify(payload))
        .digest('hex');

      if (signature !== expectedSig) {
        throw new UnauthorizedException('Invalid webhook signature');
      }
    }

    this.logger.log(`Received GitHub webhook: ${event}`);

    switch (event) {
      case 'push':
        return this.cicdService.handlePush(payload);
      case 'pull_request':
        return this.cicdService.handlePullRequest(payload);
      default:
        return { status: 'ignored', event };
    }
  }
}
