import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import type { Request } from 'express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/index.js';

@Controller('dashboard')
@UseGuards(JwtAuthGuard)
export class DashboardController {
  constructor(private prisma: PrismaService) {}

  @Get('stats')
  async getStats(@Req() req: Request) {
    const user = req.user as User;
    const userId = user.id;

    const [repoCount, scanCount, findings, recentScans] = await Promise.all([
      this.prisma.repository.count(),
      this.prisma.scan.count({ where: { userId } }),
      this.prisma.finding.findMany({
        where: { scan: { userId } },
        select: { severity: true },
      }),
      this.prisma.scan.findMany({
        where: { userId },
        include: { repository: true, scanResult: true },
        orderBy: { createdAt: 'desc' },
        take: 5,
      }),
    ]);

    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
    const lowCount = findings.filter(f => f.severity === 'LOW').length;

    const passScans = await this.prisma.scan.count({ where: { userId, policyResult: 'PASS' } });
    const blockScans = await this.prisma.scan.count({ where: { userId, policyResult: 'BLOCK' } });

    return {
      repositories: repoCount,
      totalScans: scanCount,
      totalFindings: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      passScans,
      blockScans,
      recentScans,
    };
  }
}
