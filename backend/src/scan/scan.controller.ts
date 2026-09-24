import { Controller, Post, Get, Param, Query, UseGuards, Req, Body, Res, Header } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ScanService } from './scan.service.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';

@Controller('scans')
@UseGuards(JwtAuthGuard)
export class ScanController {
  constructor(private readonly scanService: ScanService) {}

  @Post()
  async startScan(
    @Req() req: Request,
    @Body('repositoryId') repositoryId: string,
    @Body('branch') branch?: string,
  ) {
    const user = req.user as User;
    return this.scanService.startScan(user.id, repositoryId, { branch });
  }

  @Get()
  async listScans(@Req() req: Request) {
    const user = req.user as User;
    return this.scanService.getUserScans(user.id);
  }

  /**
   * Находки последнего завершённого скана одного репозитория.
   *
   * Страница «Все уязвимости» раньше склеивала находки всех сканов подряд, из-за
   * чего одна и та же проблема считалась столько раз, сколько было прогонов.
   * Без `repositoryId` берётся репозиторий с самым свежим сканом.
   */
  @Get('findings/latest')
  async getLatestFindings(@Req() req: Request, @Query('repositoryId') repositoryId?: string) {
    const user = req.user as User;
    return this.scanService.getLatestFindings(user.id, repositoryId);
  }

  @Get(':id')
  async getScanDetails(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.scanService.getScanById(user.id, id);
  }

  /** Отчёт в формате SARIF 2.1.0 — стандарт для инструментов анализа кода. */
  @Get(':id/sarif')
  @Header('Content-Type', 'application/json')
  async getSarif(@Req() req: Request, @Param('id') id: string, @Res() res: Response) {
    const user = req.user as User;
    const sarif = await this.scanService.buildSarif(user.id, id);
    res.setHeader('Content-Disposition', `attachment; filename="kmg-scan-${id}.sarif"`);
    return res.json(sarif);
  }

  /** Выгрузка отчёта в GitHub Code Scanning (вкладка Security репозитория). */
  @Post(':id/sarif/upload')
  async uploadSarif(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.scanService.uploadSarifToGithub(user.id, id);
  }

  /** Статус по каждому обязательному требованию ИБ-01…ИБ-08 с доказательствами. */
  @Get(':id/requirements')
  async getRequirements(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.scanService.getRequirements(user.id, id);
  }

  /** Матрица функций ИБ: реализован ли каждый контроль и чем это подтверждено. */
  @Get(':id/controls')
  async getSecurityControls(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.scanService.getSecurityControls(user.id, id);
  }

  @Get(':id/tree')
  async getScanFileTree(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.scanService.getScanFileTree(user.id, id);
  }

  @Get(':id/architecture')
  async getScanArchitecture(@Req() req: Request, @Param('id') id: string) {
    const user = req.user as User;
    return this.scanService.getScanArchitecture(user.id, id);
  }

  @Get(':id/file')
  async getScanFileContent(
    @Req() req: Request,
    @Param('id') id: string,
    @Query('path') filePath: string,
  ) {
    const user = req.user as User;
    return this.scanService.getScanFileContent(user.id, id, filePath || '');
  }

  @Post(':id/findings/:findingId/explain')
  async explainFinding(
    @Req() req: Request,
    @Param('id') id: string,
    @Param('findingId') findingId: string,
  ) {
    const user = req.user as User;
    return this.scanService.explainFinding(user.id, id, findingId);
  }
}
