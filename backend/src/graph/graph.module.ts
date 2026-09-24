import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { GraphService } from './graph.service.js';
import { GraphController } from './graph.controller.js';
import { AuthModule } from '../auth/auth.module.js';

@Module({
  imports: [AuthModule, PassportModule],
  controllers: [GraphController],
  providers: [GraphService],
  exports: [GraphService],
})
export class GraphModule {}
