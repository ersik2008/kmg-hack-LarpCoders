import { Module } from '@nestjs/common';
import { GithubService } from './github.service.js';
import { GithubController } from './github.controller.js';
import { GithubStatusService } from './github-status.service.js';

@Module({
  controllers: [GithubController],
  providers: [GithubService, GithubStatusService],
  exports: [GithubService, GithubStatusService],
})
export class GithubModule {}
