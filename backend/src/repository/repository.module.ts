import { Module } from '@nestjs/common';
import { RepositoryService } from './repository.service.js';
import { RepositoryController } from './repository.controller.js';
import { GithubModule } from '../github/github.module.js';

@Module({
  imports: [GithubModule],
  controllers: [RepositoryController],
  providers: [RepositoryService],
  exports: [RepositoryService],
})
export class RepositoryModule {}
