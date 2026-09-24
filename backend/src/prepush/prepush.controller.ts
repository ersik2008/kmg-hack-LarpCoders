import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { SkipThrottle } from '@nestjs/throttler';

import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';
import { PrepushService } from './prepush.service.js';
import { PrePushCheckDto } from './dto/prepush-check.dto.js';

@Controller('prepush')
@UseGuards(JwtAuthGuard)
export class PrepushController {
  constructor(private readonly prepushService: PrepushService) {}

  /**
   * Called by the git pre-push / pre-commit hook with the exact blobs that are
   * about to leave the developer's machine. `blocked: true` is the real policy
   * decision; local hooks present it as advisory feedback and CI enforces it.
   */
  @Post('check')
  @SkipThrottle()
  async check(@Req() req: Request, @Body() dto: PrePushCheckDto) {
    const user = req.user as User;
    return this.prepushService.check(user.id, dto);
  }
}
