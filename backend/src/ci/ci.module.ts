import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';

import { CiController } from './ci.controller.js';
import { CiService } from './ci.service.js';
import { PolicyModule } from '../policy/policy.module.js';
import { ScanModule } from '../scan/scan.module.js';
import { AgentModule } from '../agent/agent.module.js';
import { RequirementsModule } from '../requirements/requirements.module.js';

@Module({
  imports: [HttpModule, PolicyModule, ScanModule, AgentModule, RequirementsModule],
  controllers: [CiController],
  providers: [CiService],
  exports: [CiService],
})
export class CiModule {}
