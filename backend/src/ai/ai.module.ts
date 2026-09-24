import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { GroqService } from './groq.service.js';
import { OllamaService } from './ollama.service.js';

@Module({
  imports: [ConfigModule],
  providers: [GroqService, OllamaService],
  exports: [GroqService, OllamaService],
})
export class AiModule {}

