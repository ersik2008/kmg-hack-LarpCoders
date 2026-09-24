import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';

import { PrepushController } from './prepush.controller.js';
import { PrepushService } from './prepush.service.js';
import { PolicyModule } from '../policy/policy.module.js';
import { ScanModule } from '../scan/scan.module.js';
import { RequirementsModule } from '../requirements/requirements.module.js';

@Module({
  imports: [HttpModule, PolicyModule, ScanModule, RequirementsModule],
  controllers: [PrepushController],
  providers: [PrepushService],
  exports: [PrepushService],
})
export class PrepushModule {}
