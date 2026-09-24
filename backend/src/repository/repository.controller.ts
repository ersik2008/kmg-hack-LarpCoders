import { Controller, Post, Param, UseGuards, Req, Get } from '@nestjs/common';
import type { Request } from 'express';
import { RepositoryService } from './repository.service.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';

@Controller('repositories')
@UseGuards(JwtAuthGuard)
export class RepositoryController {
  constructor(private readonly repositoryService: RepositoryService) {}

  @Post(':id/clone')
  async cloneRepository(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    const workspacePath = await this.repositoryService.cloneRepository(user.id, id);
    return { success: true, workspacePath };
  }

  @Post(':id/cleanup')
  async cleanupRepository(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    await this.repositoryService.cleanupWorkspace(user.id, id);
    return { success: true };
  }
}
