import { Module } from '@nestjs/common';
import { PolicyService } from './policy.service.js';
import { PolicyController } from './policy.controller.js';

@Module({
  controllers: [PolicyController],
  providers: [PolicyService],
  exports: [PolicyService],
})
export class PolicyModule {}
