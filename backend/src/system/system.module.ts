import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';

import { SystemController } from './system.controller.js';
import { AiModule } from '../ai/ai.module.js';

@Module({
  imports: [HttpModule, AiModule],
  controllers: [SystemController],
})
export class SystemModule {}
