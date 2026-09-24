import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { PrismaModule } from './prisma/index.js';
import { AuthModule } from './auth/auth.module.js';
import { GithubModule } from './github/github.module.js';
import { RepositoryModule } from './repository/repository.module.js';
import { AiModule } from './ai/ai.module.js';
import { AgentModule } from './agent/agent.module.js';
import { ScanModule } from './scan/scan.module.js';
import { GraphModule } from './graph/graph.module.js';
import { PolicyModule } from './policy/policy.module.js';
import { CicdModule } from './cicd/cicd.module.js';
import { PrepushModule } from './prepush/prepush.module.js';
import { SystemModule } from './system/system.module.js';
import { CiModule } from './ci/ci.module.js';
import { DashboardModule } from './dashboard/dashboard.module.js';
import { EventsModule } from './events/events.module.js';
import { PromptInjectionGuard } from './common/middleware/prompt-injection.guard.js';

@Module({
  imports: [
    // Global configuration from .env
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '../.env',
    }),

    // Rate limiting
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60000,
          limit: 100,
        },
      ],
    }),

    // Database
    PrismaModule,

    // Поток событий для живых обновлений в UI
    EventsModule,
    
    // Feature Modules
    AuthModule,
    GithubModule,
    RepositoryModule,
    AiModule,
    AgentModule,
    PolicyModule,
    ScanModule,
    GraphModule,
    CicdModule,
    PrepushModule,
    SystemModule,
    CiModule,
    DashboardModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // Apply rate limiting globally
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Apply prompt injection guard to all scan and agent-related routes
    consumer
      .apply(PromptInjectionGuard)
      .forRoutes('scans', 'cicd');
  }
}
