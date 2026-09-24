import { Module } from '@nestjs/common';
import { ScanService } from './scan.service.js';
import { ScanController } from './scan.controller.js';
import { RepositoryModule } from '../repository/repository.module.js';
import { AgentModule } from '../agent/agent.module.js';
import { HttpModule } from '@nestjs/axios';
import { PolicyModule } from '../policy/policy.module.js';

import { BuiltinScannerService } from './builtin-scanner.service.js';
import { ArchitectureService } from './architecture.service.js';
import { SarifService } from './sarif.service.js';

import { AiModule } from '../ai/ai.module.js';
import { GithubModule } from '../github/github.module.js';
import { RequirementsModule } from '../requirements/requirements.module.js';

@Module({
  imports: [RepositoryModule, AgentModule, HttpModule, PolicyModule, AiModule, GithubModule, RequirementsModule],
  controllers: [ScanController],
  providers: [ScanService, BuiltinScannerService, ArchitectureService, SarifService],
  exports: [ScanService, BuiltinScannerService, ArchitectureService, SarifService],
})
export class ScanModule {}
