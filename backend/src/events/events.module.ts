import { Global, Module } from '@nestjs/common';

import { EventsController } from './events.controller.js';
import { EventsService } from './events.service.js';

/**
 * Глобальный: события публикуют несколько модулей (prepush, scan, github),
 * и заводить импорт в каждом из них ради одного сервиса незачем.
 */
@Global()
@Module({
  controllers: [EventsController],
  providers: [EventsService],
  exports: [EventsService],
})
export class EventsModule {}
