import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module.js';
import { OllamaService } from './ai/ollama.service.js';
import { json, raw, urlencoded } from 'express';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter.js';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor.js';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule);
  const ollamaService = app.get(OllamaService);

  // OllamaService already calls warmUp in onModuleInit, but we explicitly
  // call it here too to log the result before the first request arrives.
  void ollamaService.warmUp();

  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT', 3000);
  const frontendUrl = configService.get<string>(
    'FRONTEND_URL',
    'http://localhost:5173',
  );

  // The pre-push hook posts the blobs that are about to be pushed, which is
  // well beyond the 100kb express default.
  const bodyLimit = configService.get<string>('API_BODY_LIMIT', '45mb');

  // CI присылает репозиторий как tar.gz. Сырой парсер должен стоять ДО json,
  // иначе express попытается разобрать бинарь как JSON и запрос упадёт.
  const archiveLimit = configService.get<string>('CI_ARCHIVE_LIMIT', '80mb');
  app.use('/api/ci/scan', raw({ type: () => true, limit: archiveLimit }));
  app.use('/api/ci/scan/summary', raw({ type: () => true, limit: archiveLimit }));

  app.use(json({ limit: bodyLimit }));
  app.use(urlencoded({ extended: true, limit: bodyLimit }));

  // Global prefix for all API routes
  app.setGlobalPrefix('api');

  // Enable CORS for frontend
  app.enableCors({
    origin: frontendUrl,
    credentials: true,
  });

  // Global validation pipe — strips unknown properties and auto-transforms types
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Global exception filter — catches all errors and redacts secrets
  app.useGlobalFilters(new GlobalExceptionFilter());

  // Global logging interceptor — logs every request/response with duration
  app.useGlobalInterceptors(new LoggingInterceptor());

  await app.listen(port);
  logger.log(`🚀 KMG Security Agent API running on http://localhost:${port}`);
  logger.log(`📖 API prefix: /api`);
  logger.log(`🛡️ Security hardening: exception filter, input validation, rate limiting, prompt injection guard`);
}

await bootstrap();
