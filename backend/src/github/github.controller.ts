import { Controller, Get, Param, Query, UseGuards, Req } from '@nestjs/common';
import type { Request } from 'express';
import { GithubService } from './github.service.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';

@Controller('github')
@UseGuards(JwtAuthGuard)
export class GithubController {
  constructor(private readonly githubService: GithubService) {}

  @Get('repositories')
  async getRepositories(@Req() req: Request) {
    const user = req.user as User;
    return this.githubService.getUserRepositories(user.id);
  }

  /**
   * Активность по репозиториям: последний коммит и открытые пулл-реквесты.
   * Вынесено из основного списка — это 2 вызова GitHub API на репозиторий.
   */
  @Get('repositories/activity')
  async getRepositoriesActivity(@Req() req: Request, @Query('ids') ids?: string) {
    const user = req.user as User;
    const repositoryIds = (ids || '').split(',').map(v => v.trim()).filter(Boolean);
    return this.githubService.getRepositoriesActivity(user.id, repositoryIds);
  }

  @Get('repositories/:id')
  async getRepository(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.githubService.getRepositoryById(user.id, id);
  }
}
