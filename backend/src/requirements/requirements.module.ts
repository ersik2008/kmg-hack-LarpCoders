import { Module } from '@nestjs/common';

import { RequirementsService } from './requirements.service.js';

@Module({
  providers: [RequirementsService],
  exports: [RequirementsService],
})
export class RequirementsModule {}
