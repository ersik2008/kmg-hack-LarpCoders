import { Injectable, Logger } from '@nestjs/common';
import { OllamaService } from '../ai/ollama.service.js';
import { AgentToolsService } from './agent-tools.service.js';
import { PrismaService } from '../prisma/index.js';
import { InvestigationService } from './investigation.service.js';
import { SecurityControlsService } from './security-controls.service.js';

@Injectable()
export class AgentService {
  private readonly logger = new Logger(AgentService.name);

  constructor(
    private groqService: OllamaService,
    private toolsService: AgentToolsService,
    private prisma: PrismaService,
    private investigationService: InvestigationService,
    private controlsService: SecurityControlsService,
  ) {}

  private getToolDefinitions() {
    return [
      {
        type: 'function',
        function: {
          name: 'list_repository_files',
          description: 'List all repository files and directory structure in the isolated workspace',
          parameters: { type: 'object', properties: {} },
        },
      },
      {
        type: 'function',
        function: {
          name: 'get_repository_structure',
          description: 'Alias for list_repository_files',
          parameters: { type: 'object', properties: {} },
        },
      },
      {
        type: 'function',
        function: {
          name: 'get_file',
          description: 'Read the contents of a specific file',
          parameters: {
            type: 'object',
            properties: {
              file_path: { type: 'string', description: 'Path to the file relative to repository root' }
            },
            required: ['file_path']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_file_range',
          description: 'Read a specific line range from a file',
          parameters: {
            type: 'object',
            properties: {
              file_path: { type: 'string', description: 'Path to the file relative to repository root' },
              start_line: { type: 'number', description: 'Start line number (1-indexed)' },
              end_line: { type: 'number', description: 'End line number' }
            },
            required: ['file_path', 'start_line', 'end_line']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'search_code',
          description: 'Search for text, function names, or patterns in all codebase files',
          parameters: {
            type: 'object',
            properties: {
              query: { type: 'string', description: 'The search query or keyword' }
            },
            required: ['query']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'find_files',
          description: 'Find files matching a specific name pattern or extension (e.g. .env, package.json, schema.prisma)',
          parameters: {
            type: 'object',
            properties: {
              pattern: { type: 'string', description: 'Pattern or filename to find' }
            },
            required: ['pattern']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_dependencies',
          description: 'Inspect dependencies and manifests in the project (package.json, requirements.txt, etc.)',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_findings',
          description: 'Get all security vulnerabilities and secrets detected by scanners for this scan',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_finding',
          description: 'Retrieve details for a single specific finding ID',
          parameters: {
            type: 'object',
            properties: {
              finding_id: { type: 'string', description: 'The UUID of the finding' }
            },
            required: ['finding_id']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_related_findings',
          description: 'Find related vulnerabilities sharing the same file or vulnerability vector',
          parameters: {
            type: 'object',
            properties: {
              finding_id: { type: 'string', description: 'The UUID of the finding' }
            },
            required: ['finding_id']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'inspect_function',
          description: 'Extract and inspect the body of a specific function or class symbol in a file',
          parameters: {
            type: 'object',
            properties: {
              file_path: { type: 'string', description: 'File path' },
              symbol: { type: 'string', description: 'Function or symbol name' }
            },
            required: ['file_path', 'symbol']
          }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_repository_metadata',
          description: 'Get repository summary metadata (file count, sample files, etc.)',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'get_git_diff',
          description: 'Inspect recent git commit diff in the repository workspace',
          parameters: { type: 'object', properties: {} }
        }
      },
      {
        type: 'function',
        function: {
          name: 'build_relationship',
          description: 'Register an evidence-based relationship in the security graph (e.g. data flow from entry point to vulnerable sink). Requires concrete code evidence.',
          parameters: {
            type: 'object',
            properties: {
              source: { type: 'string', description: 'Source component, user input, or caller' },
              target: { type: 'string', description: 'Target sink, executed query, or impacted component' },
              type: { type: 'string', enum: ['FLOWS_TO', 'CALLS', 'DEPENDS_ON', 'AFFECTS', 'EXECUTES_IN', 'CAUSES'] },
              filePath: { type: 'string', description: 'Source file where evidence was observed' },
              line: { type: 'number', description: 'Line number of evidence' },
              symbol: { type: 'string', description: 'Function or variable symbol' },
              reason: { type: 'string', description: 'Concrete reason/evidence explaining how source reaches target' },
              confidence: { type: 'string', enum: ['CONFIRMED', 'POTENTIAL'], description: 'CONFIRMED only if verified in code; POTENTIAL if inferred' }
            },
            required: ['source', 'target', 'type', 'reason']
          }
        }
      }
    ];
  }

  /**
   * Runs the AI investigation for a scan.
   *
   * Stage 0 (optional recon) lets the model look around the repository with
   * read-only tools; the real work — per-finding triage, attack-path graph and
   * the report — happens in InvestigationService as small independent calls
   * that do not re-send a growing transcript.
   */
  async investigateScan(scanId: string, workspacePath: string) {
    this.logger.log(`Starting AI investigation for scan ${scanId}`);

    if (!this.groqService.isConfigured()) {
      await this.storeUnavailableSummary(scanId, 'Ollama не настроен');
      throw new Error('Ollama is not configured — AI analysis unavailable');
    }

    if (process.env.AI_RECON_ENABLED === 'true') {
      await this.recon(scanId, workspacePath);
    }

    // Проверка функций ИБ: реализованы ли контроли безопасности вообще.
    // Идёт первой — её результат не зависит от находок сканеров и полезен даже
    // тогда, когда уязвимостей не найдено ни одной.
    let controls: Awaited<ReturnType<SecurityControlsService['assess']>> | null = null;
    try {
      controls = await this.controlsService.assess(scanId, workspacePath);
    } catch (err: any) {
      this.logger.warn(`Security control assessment failed: ${err.message}`);
    }

    const outcome = await this.investigationService.run(scanId, workspacePath);
    (outcome as any).controls = controls;

    if (outcome.triaged === 0 && !outcome.reportGenerated) {
      await this.storeUnavailableSummary(
        scanId,
        outcome.stageErrors.join('; ') || 'модель не вернула результат',
      );
      throw new Error(`AI investigation produced no result: ${outcome.stageErrors.join('; ') || 'unknown'}`);
    }

    return outcome;
  }

  /**
   * Optional free-form recon pass. Bounded on purpose: it is useful colour for
   * the report, but it must never consume the token budget the triage needs.
   */
  private async recon(scanId: string, workspacePath: string) {
    const systemPrompt = `Ты — инженер по безопасности, который бегло осматривает репозиторий.
Используй инструменты, чтобы понять стек, точки входа и где обрабатываются внешние данные.
Не выдумывай файлы. Ответь кратко (до 10 строк) по-русски.`;

    const messages: any[] = [
      { role: 'user', content: 'Осмотри репозиторий и опиши стек, точки входа и потенциально опасные места.' },
    ];

    const tools = this.getToolDefinitions().filter(t =>
      ['list_repository_files', 'get_repository_metadata', 'get_dependencies', 'search_code'].includes(
        t.function.name,
      ),
    );

    const maxIterations = Number(process.env.AI_RECON_ITERATIONS || 3);
    const maxToolChars = Number(process.env.AGENT_TOOL_RESULT_CHARS || 2500);

    for (let i = 0; i < maxIterations; i++) {
      const response = await this.groqService.invokeToolCalling(systemPrompt, messages, tools);
      if (!response) {
        this.logger.warn('Recon stage stopped: Ollama returned no response');
        return;
      }

      messages.push(response);

      if (!response.tool_calls?.length) {
        if (response.content) {
          await this.prisma.aIAnalysis.create({
            data: { scanId, type: 'repository_recon', response: response.content, model: 'ollama' },
          }).catch(() => {});
        }
        return;
      }

      for (const call of response.tool_calls) {
        let args: any = {};
        try {
          args = JSON.parse(call.function.arguments || '{}');
        } catch {
          args = {};
        }

        let result = '';
        try {
          switch (call.function.name) {
            case 'list_repository_files':
              result = await this.toolsService.getRepositoryStructure(workspacePath);
              break;
            case 'get_repository_metadata':
              result = await this.toolsService.getRepositoryMetadata(workspacePath);
              break;
            case 'get_dependencies':
              result = await this.toolsService.getDependencies(workspacePath);
              break;
            case 'search_code':
              result = await this.toolsService.searchCode(workspacePath, args.query || '');
              break;
            default:
              result = `Tool '${call.function.name}' is not available during recon.`;
          }
        } catch (err: any) {
          result = `Error executing ${call.function.name}: ${err.message}`;
        }

        messages.push({
          role: 'tool',
          tool_call_id: call.id,
          name: call.function.name,
          content: result.length > maxToolChars ? `${result.slice(0, maxToolChars)}\n...[truncated]` : result,
        } as any);
      }
    }
  }

  /**
   * Records, clearly labelled, that no AI analysis happened. Never AI-styled
   * prose that could pass for an analysis the model did not perform.
   */
  private async storeUnavailableSummary(scanId: string, reason: string) {
    const existing = await this.prisma.aIAnalysis.findFirst({ where: { scanId } });
    if (existing) return;

    const findings = await this.prisma.finding.findMany({ where: { scanId } });
    const bySeverity = (sev: string) => findings.filter(f => f.severity === sev).length;

    const summary = [
      `[AI-анализ не выполнен — ${reason}]`,
      '',
      findings.length > 0
        ? `Ниже — только детерминированный итог по находкам сканеров: всего ${findings.length} ` +
          `(CRITICAL: ${bySeverity('CRITICAL')}, HIGH: ${bySeverity('HIGH')}, ` +
          `MEDIUM: ${bySeverity('MEDIUM')}, LOW: ${bySeverity('LOW')}, INFO: ${bySeverity('INFO')}).`
        : 'Сканеры не обнаружили поддерживаемых уязвимостей. Интерпретация не выполнялась.',
    ].join('\n');

    await this.prisma.aIAnalysis.create({
      data: { scanId, type: 'scanner_summary', response: summary, model: 'none' },
    }).catch(() => {});
  }
}
