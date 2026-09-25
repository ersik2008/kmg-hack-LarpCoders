import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/index.js';
import { RequirementsService } from '../requirements/requirements.service.js';

@Injectable()
export class MarkdownService {
  constructor(
    private prisma: PrismaService,
    private requirementsService: RequirementsService
  ) {}

  async build(userId: string, scanId: string): Promise<string> {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, userId },
      include: {
        repository: true,
        findings: true,
        scanResult: true,
      }
    });

    if (!scan) throw new NotFoundException('Scan not found');

    const reqsData = await this.requirementsService.getForScan(scanId);
    const reqs = reqsData.requirements || [];
    
    let md = `# Отчет о результатах сканирования ИБ\n\n`;
    md += `**Репозиторий:** ${scan.repository.fullName}\n`;
    md += `**Ветка:** ${scan.branch || 'main'}\n`;
    md += `**Коммит:** ${scan.commitSha || 'N/A'}\n`;
    md += `**Дата сканирования:** ${scan.createdAt.toLocaleString('ru-RU')}\n`;
    md += `**Результат политики:** ${scan.policyResult || 'N/A'}\n`;
    md += `**Оценка риска:** ${scan.riskScore}/10\n`;
    md += `**Всего найдено уязвимостей:** ${scan.findings.length}\n\n`;

    md += `## 1. Сводка по обязательным требованиям (ТЗ п. 4.5)\n\n`;
    md += `| ID | Требование | Статус |\n|---|---|---|\n`;
    
    for (const req of reqs) {
      let statusIcon = req.status === 'PASS' ? '✅ Выполнено' : req.status === 'VIOLATION' ? '❌ Нарушение' : '⚠️ ' + req.status;
      md += `| **${req.requirementId}** | ${req.title} | ${statusIcon} |\n`;
    }

    md += `\n## 2. Детализация выявленных нарушений\n\n`;
    
    if (scan.findings.length === 0) {
      md += `*Нарушений и уязвимостей не выявлено.*\n`;
    } else {
      for (const [index, f] of scan.findings.entries()) {
        md += `### 2.${index + 1}. [${f.severity}] ${f.title}\n\n`;
        md += `* **Правило:** ${f.ruleId || 'N/A'}\n`;
        md += `* **Сканер:** ${f.scanner}\n`;
        if (f.filePath) {
          md += `* **Местоположение:** \`${f.filePath}\`${f.startLine ? ` (строка ${f.startLine})` : ''}\n`;
        }
        if (f.description) {
          md += `\n**Описание:**\n${f.description}\n`;
        }
        const metadata: any = f.metadata || {};
        if (metadata.recommendation) {
          md += `\n**Рекомендация:**\n${metadata.recommendation}\n`;
        }
        md += `\n---\n\n`;
      }
    }

    return md;
  }
}
