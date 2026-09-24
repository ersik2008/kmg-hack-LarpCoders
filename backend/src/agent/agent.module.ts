import { Module } from '@nestjs/common';
import { AgentService } from './agent.service.js';
import { AgentToolsService } from './agent-tools.service.js';
import { InvestigationService } from './investigation.service.js';
import { SecurityControlsService } from './security-controls.service.js';
import { AiModule } from '../ai/ai.module.js';

@Module({
  imports: [AiModule],
  providers: [AgentService, AgentToolsService, InvestigationService, SecurityControlsService],
  exports: [AgentService, SecurityControlsService],
})
export class AgentModule {}
