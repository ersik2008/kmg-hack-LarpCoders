import { Body, Controller, Get, Put, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { PolicyService, PolicySettings } from './policy.service.js';

@Controller('policy')
@UseGuards(JwtAuthGuard)
export class PolicyController {
  constructor(private readonly policyService: PolicyService) {}

  /** Live gate configuration, read from the `policies` table. */
  @Get()
  async getSettings(): Promise<PolicySettings> {
    return this.policyService.getSettings();
  }

  /**
   * Persists the gate configuration. The values returned here are what the
   * scan pipeline and the pre-push hook actually enforce.
   */
  @Put()
  async updateSettings(@Body() body: unknown): Promise<PolicySettings> {
    return this.policyService.updateSettings(body);
  }
}
