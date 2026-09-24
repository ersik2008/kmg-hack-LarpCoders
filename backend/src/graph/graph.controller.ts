import { Controller, Get, Param, Query, UseGuards, Req } from '@nestjs/common';
import type { Request } from 'express';
import { GraphService } from './graph.service.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';

@Controller('graph')
@UseGuards(JwtAuthGuard)
export class GraphController {
  constructor(private readonly graphService: GraphService) {}

  /** Репозитории с завершёнными сканами — для переключателя на странице. */
  @Get('attack-paths/repositories')
  async getScannedRepositories(@Req() req: Request) {
    const user = req.user as User;
    return this.graphService.getScannedRepositories(user.id);
  }

  /** Без `repositoryId` отдаётся последний завершённый скан пользователя. */
  @Get('attack-paths')
  async getAttackPaths(@Req() req: Request, @Query('repositoryId') repositoryId?: string) {
    const user = req.user as User;
    return this.graphService.getAttackPaths(user.id, repositoryId);
  }

  @Get(':scanId')
  async getGraphForScan(@Param('scanId') scanId: string) {
    return this.graphService.getGraphData(scanId);
  }
}

