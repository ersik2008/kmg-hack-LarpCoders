import { Module } from '@nestjs/common';
import { CicdService } from './cicd.service.js';
import { CicdController } from './cicd.controller.js';
import { ScanModule } from '../scan/scan.module.js';
import { GithubModule } from '../github/github.module.js';

@Module({
  imports: [ScanModule, GithubModule],
  controllers: [CicdController],
  providers: [CicdService],
  exports: [CicdService],
})
export class CicdModule {}
