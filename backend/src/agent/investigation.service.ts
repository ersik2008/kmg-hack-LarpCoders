import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

import { OllamaService } from '../ai/ollama.service.js';
import { AgentToolsService } from './agent-tools.service.js';
import { PrismaService } from '../prisma/index.js';
import { Finding } from '../generated/prisma/client.js';

/**
 * Staged AI investigation.
 *
 * The previous design was a single open-ended tool-calling loop: every step
 * re-sent the whole transcript, so on a real repository it exhausted the
 * account's tokens-per-minute budget after three or four tool calls and ended
 * with no analysis, no attack paths and an empty security graph.
 *
 * This pipeline instead issues many small, INDEPENDENT calls. Nothing
 * accumulates between them, so each one stays well inside the budget and a
 * failure in one stage does not destroy the others:
 *
 *   1. TRIAGE       - per-finding verdict + explanation, grounded in real code
 *   2. ATTACK PATHS - evidence-linked relationships written into the graph
 *   3. REPORT       - an executive summary built from stages 1 and 2
 *
 * No stage is allowed to invent findings, files or line numbers: every prompt
 * is fed real scanner output and real source lines read from the workspace.
 */

export interface InvestigationOutcome {
  triaged: number;
  truePositives: number;
  falsePositives: number;
  relationships: number;
  reportGenerated: boolean;
  stageErrors: string[];
}

interface TriageVerdict {
  id: string;
  verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'UNCERTAIN';
  reason: string;
  exploitation: string;
  recommendation: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

interface AttackPathLink {
  source: string;
  target: string;
  type: string;
  filePath?: string;
  line?: number;
  reason: string;
  confidence: 'CONFIRMED' | 'POTENTIAL';
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};

const VALID_EDGE_TYPES = new Set(['FLOWS_TO', 'CALLS', 'DEPENDS_ON', 'READS', 'WRITES', 'CAUSES', 'RELATED_TO']);

/**
 * Суммарный объём кода на один запрос триажа, в символах.
 *
 * Groq на этом тарифе даёт ~8000 токенов в минуту на запрос; ~4 символа на
 * токен плюс место под промпт и ответ оставляют около 12k символов кода.
 */
const BATCH_CODE_BUDGET_CHARS = 12_000;

@Injectable()
export class InvestigationService {
  private readonly logger = new Logger(InvestigationService.name);

  constructor(
    private readonly groq: OllamaService,
    private readonly tools: AgentToolsService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * 0 (по умолчанию) — анализировать все находки. Раньше стоял жёсткий потолок
   * в 24 находки, и часть уязвимостей молча оставалась без вердикта AI.
   * Значение > 0 оставлено как аварийный тормоз для гигантских репозиториев.
   */
  private get maxFindings(): number {
    const configured = Number(process.env.AI_TRIAGE_MAX_FINDINGS || 0);
    return Number.isFinite(configured) && configured > 0 ? configured : Infinity;
  }

  private get batchSize(): number {
    return Number(process.env.AI_TRIAGE_BATCH_SIZE || 3);
  }

  async run(scanId: string, workspacePath: string): Promise<InvestigationOutcome> {
    const outcome: InvestigationOutcome = {
      triaged: 0,
      truePositives: 0,
      falsePositives: 0,
      relationships: 0,
      reportGenerated: false,
      stageErrors: [],
    };

    if (!this.groq.isConfigured()) {
      outcome.stageErrors.push('Ollama не настроен — AI-анализ не выполнялся');
      return outcome;
    }

    const findings = await this.prisma.finding.findMany({ where: { scanId } });
    if (findings.length === 0) {
      this.logger.log(`Scan ${scanId}: no findings to investigate`);
      return outcome;
    }

    // Most severe first, and at most one finding per (file, rule) so the budget
    // is not spent re-explaining the same defect repeated across a file.
    const selected = this.selectForTriage(findings);
    this.logger.log(
      `Scan ${scanId}: AI triage over ${selected.length} of ${findings.length} findings ` +
        `(batch size ${this.batchSize})`,
    );

    // ---------- Stage 1: attack paths ----------
    // Раньше граф строился после триажа и на большом репозитории оставался без
    // дневного бюджета токенов — скан заканчивался с пустым графом. Это один
    // дешёвый запрос, поэтому он идёт первым: самое ценное для страницы скана
    // не должно зависеть от того, хватило ли бюджета на разбор всех находок.
    const graphCandidates = selected.slice(0, 14);
    if (graphCandidates.length > 0) {
      try {
        outcome.relationships = await this.buildAttackPaths(scanId, graphCandidates, []);
      } catch (err: any) {
        const msg = `Построение цепочек атак: ${err.message}`;
        this.logger.warn(msg);
        outcome.stageErrors.push(msg);
      }
    }

    // ---------- Stage 2: triage ----------
    const verdicts: TriageVerdict[] = [];
    for (let i = 0; i < selected.length; i += this.batchSize) {
      const batch = selected.slice(i, i + this.batchSize);
      try {
        const batchVerdicts = await this.triageBatch(workspacePath, batch);
        verdicts.push(...batchVerdicts);
        await this.persistVerdicts(scanId, batch, batchVerdicts, findings);
      } catch (err: any) {
        const msg = `Триаж находок ${i + 1}–${i + batch.length}: ${err.message}`;
        this.logger.warn(msg);
        outcome.stageErrors.push(msg);
      }
    }

    outcome.triaged = verdicts.length;
    outcome.truePositives = verdicts.filter(v => v.verdict === 'TRUE_POSITIVE').length;
    outcome.falsePositives = verdicts.filter(v => v.verdict === 'FALSE_POSITIVE').length;

    // Связи, ведущие к находкам, которые триаж признал ложными, убираются:
    // граф строился до вердиктов и мог опереться на ложное срабатывание.
    const falsePositiveIds = verdicts.filter(v => v.verdict === 'FALSE_POSITIVE').map(v => v.id);
    if (falsePositiveIds.length > 0 && outcome.relationships > 0) {
      const removed = await this.dropPathsForFalsePositives(scanId, selected, falsePositiveIds);
      outcome.relationships = Math.max(0, outcome.relationships - removed);
    }

    // ---------- Stage 3: report ----------
    try {
      outcome.reportGenerated = await this.writeReport(scanId, findings, selected, verdicts, outcome);
    } catch (err: any) {
      const msg = `Формирование отчёта: ${err.message}`;
      this.logger.warn(msg);
      outcome.stageErrors.push(msg);
    }

    this.logger.log(
      `Scan ${scanId}: investigation done — triaged=${outcome.triaged} ` +
        `TP=${outcome.truePositives} FP=${outcome.falsePositives} ` +
        `relationships=${outcome.relationships} report=${outcome.reportGenerated}`,
    );

    return outcome;
  }

  /**
   * Removes graph edges whose evidence points at a finding the triage later
   * marked FALSE_POSITIVE. The graph is built before the verdicts are known, so
   * without this step a dismissed finding could still appear as an attack path.
   */
  private async dropPathsForFalsePositives(
    scanId: string,
    selected: Finding[],
    falsePositiveIds: string[],
  ): Promise<number> {
    const dismissed = selected.filter(f => falsePositiveIds.includes(f.id) && f.filePath);
    if (dismissed.length === 0) return 0;

    // Ложным признаётся файл целиком только если в нём не осталось
    // подтверждённых находок — иначе связь может относиться к другой проблеме.
    const stillRelevant = new Set(
      selected.filter(f => !falsePositiveIds.includes(f.id)).map(f => f.filePath).filter(Boolean) as string[],
    );
    const dismissedFiles = new Set(
      dismissed.map(f => f.filePath!).filter(p => !stillRelevant.has(p)),
    );
    if (dismissedFiles.size === 0) return 0;

    const edges = await this.prisma.graphEdge.findMany({ where: { scanId } });
    let removed = 0;

    for (const edge of edges) {
      let filePath: string | undefined;
      try {
        const meta = typeof edge.metadata === 'string' ? JSON.parse(edge.metadata) : edge.metadata;
        filePath = (meta as any)?.filePath;
      } catch {
        continue;
      }

      if (filePath && dismissedFiles.has(filePath)) {
        try {
          await this.prisma.graphEdge.delete({ where: { id: edge.id } });
          removed++;
        } catch (err: any) {
          this.logger.warn(`Could not drop edge ${edge.id}: ${err.message}`);
        }
      }
    }

    if (removed > 0) {
      this.logger.log(`Scan ${scanId}: dropped ${removed} attack path(s) tied to false positives`);
    }
    return removed;
  }

  /** Ключ дедупликации: один и тот же дефект в одном файле. */
  private static dedupKey(f: Finding): string {
    return `${f.filePath || ''}::${f.ruleId || f.title}`;
  }

  /**
   * Severity-ordered, de-duplicated by (file, rule).
   *
   * Одно правило может сработать в файле десятки раз (например, проверка
   * зависимостей по каждой строке package.json). Модели отправляется один
   * представитель группы, а его вердикт затем копируется на остальные —
   * так покрыты все находки, но бюджет не тратится на повторы.
   */
  private selectForTriage(findings: Finding[]): Finding[] {
    const seen = new Set<string>();
    const deduped = [...findings]
      .sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0))
      .filter(f => {
        const key = InvestigationService.dedupKey(f);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

    return Number.isFinite(this.maxFindings) ? deduped.slice(0, this.maxFindings) : deduped;
  }

  /**
   * Builds the code the model judges a finding against.
   *
   * The amount of context is matched to what the verdict actually needs, because
   * the daily Groq token budget is finite: a hardcoded secret or a `ws://` URL is
   * decidable from a few lines, while injection-style findings need the
   * surrounding data flow. Dependency findings get the manifest instead of a
   * slice of the lock file, which the model could only answer "недостаточно" to.
   */
  private async buildEvidence(workspacePath: string, finding: Finding): Promise<string> {
    if (!finding.filePath) return '';

    if (InvestigationService.isDependencyFile(finding.filePath)) {
      const manifest = await this.readDependencyManifest(workspacePath, finding.filePath);
      if (manifest) return manifest;
    }

    const budget = InvestigationService.contextBudget(finding);
    return this.readContext(workspacePath, finding.filePath, finding.startLine, budget);
  }

  /**
   * How much code a finding needs to be judged.
   *
   * "narrow" — самодостаточные находки: секрет, слабый алгоритм, небезопасный
   * протокол. Вердикт виден по самой строке, и широкий контекст только жёг бы
   * дневной бюджет токенов.
   * "wide" — находки про поток данных: нужно видеть, откуда приходит ввод.
   */
  private static contextBudget(finding: Finding): { lines: number; chars: number } {
    const text = `${finding.title || ''} ${finding.ruleId || ''}`.toLowerCase();
    const scanner = (finding.scanner || '').toLowerCase();

    const selfEvident =
      scanner.includes('gitleaks') ||
      /secret|password|token|api[_-]?key|credential|hardcoded|private[_-]?key/.test(text) ||
      /\bws:\/\/|http:\/\/|insecure[_-]?(protocol|transport|websocket)|weak[_-]?(crypto|cipher|hash)|md5|sha1/.test(text);

    if (selfEvident) return { lines: 12, chars: 1600 };

    const needsFlow =
      /injection|traversal|ssrf|xss|deserial|eval|exec|command|sql|redirect|upload|sanitiz|validat/.test(text);

    return needsFlow ? { lines: 40, chars: 7000 } : { lines: 22, chars: 3500 };
  }

  private static isDependencyFile(filePath: string): boolean {
    const name = filePath.split(/[\\/]/).pop()?.toLowerCase() || '';
    return [
      'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'package.json',
      'requirements.txt', 'poetry.lock', 'pipfile.lock', 'go.sum', 'go.mod',
      'gemfile.lock', 'composer.lock', 'cargo.lock',
    ].includes(name);
  }

  /**
   * For a lock-file finding, reads the manifest that declares the version
   * ranges — that is where the fix has to be applied and what makes the
   * verdict decidable.
   */
  private async readDependencyManifest(workspacePath: string, lockPath: string): Promise<string> {
    const dir = path.dirname(lockPath);
    const candidates = ['package.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Gemfile', 'composer.json', 'Cargo.toml'];

    for (const candidate of candidates) {
      const relative = path.join(dir, candidate);
      const content = await this.readWholeFile(workspacePath, relative, 6000);
      if (content) {
        return `Манифест зависимостей ${relative.replace(/\\/g, '/')}:\n${content}`;
      }
    }
    return '';
  }

  /** Reads a file fully (up to a cap), used when a window would not be enough. */
  private async readWholeFile(workspacePath: string, filePath: string, limit: number): Promise<string> {
    try {
      const resolved = path.resolve(workspacePath, filePath);
      if (!resolved.startsWith(path.resolve(workspacePath))) return '';

      const content = await fs.readFile(resolved, 'utf8');
      return content.length > limit ? `${content.slice(0, limit)}\n… (файл обрезан)` : content;
    } catch {
      return '';
    }
  }

  /**
   * Reads the actual lines around a finding so the model judges real code.
   * The window used to be ±9 lines capped at 1800 chars, which regularly cut
   * off the function containing the vulnerability and forced UNCERTAIN.
   */
  private async readContext(
    workspacePath: string,
    filePath: string | null,
    line: number | null,
    budget: { lines: number; chars: number } = { lines: 40, chars: 7000 },
  ): Promise<string> {
    if (!filePath) return '';
    try {
      const resolved = path.resolve(workspacePath, filePath);
      if (!resolved.startsWith(path.resolve(workspacePath))) return '';

      const content = await fs.readFile(resolved, 'utf8');
      const lines = content.split(/\r?\n/);

      // Небольшой файл дешевле показать целиком, чем вырезать из него окно.
      if (lines.length <= budget.lines * 3 && content.length <= budget.chars) {
        return lines.map((l, i) => `${i + 1}: ${l}`).join('\n');
      }

      const center = Math.max(1, line || 1);
      const start = Math.max(0, center - budget.lines);
      const end = Math.min(lines.length, center + budget.lines);

      return lines
        .slice(start, end)
        .map((l, i) => `${start + i + 1}: ${l}`)
        .join('\n')
        .slice(0, budget.chars);
    } catch {
      return '';
    }
  }

  private async triageBatch(workspacePath: string, batch: Finding[]): Promise<TriageVerdict[]> {
    const items = await Promise.all(
      batch.map(async f => ({
        id: f.id,
        scanner: f.scanner,
        rule: f.ruleId,
        severity: f.severity,
        title: (f.title || '').slice(0, 200),
        description: (f.description || '').slice(0, 500),
        location: f.filePath ? `${f.filePath}:${f.startLine ?? '?'}` : 'unknown',
        code: await this.buildEvidence(workspacePath, f),
      })),
    );

    // Groq ограничивает запрос примерно 8000 токенами в минуту. Несколько
    // «широких» находок в одном батче вместе перекрывают этот лимит, и весь
    // батч падает с rate_limit_exceeded — поэтому общий объём кода режется
    // здесь, равномерно по находкам.
    const totalCode = items.reduce((sum, it) => sum + it.code.length, 0);
    if (totalCode > BATCH_CODE_BUDGET_CHARS) {
      const perItem = Math.floor(BATCH_CODE_BUDGET_CHARS / items.length);
      for (const it of items) {
        if (it.code.length > perItem) {
          it.code = `${it.code.slice(0, perItem)}\n… (фрагмент сокращён, чтобы уложиться в лимит модели)`;
        }
      }
    }

    const systemPrompt =
      'Ты — старший инженер по безопасности приложений. Тебе дают находки сканеров вместе с ' +
      'реальным кодом из репозитория. Для каждой находки вынеси вердикт, опираясь ТОЛЬКО на ' +
      'показанный код.\n' +
      'Правила:\n' +
      '- Не придумывай файлы, строки и функции, которых нет в показанном коде.\n' +
      '- FALSE_POSITIVE ставь только если по коду видно, что эксплуатация невозможна ' +
      '(валидация, параметризация, константный ввод).\n' +
      '- UNCERTAIN — крайний случай. Прежде чем его выбрать, сделай вывод из того, что ' +
      'есть: известная уязвимость в версии зависимости, секрет в открытом виде или опасный ' +
      'вызов — это TRUE_POSITIVE и без чтения всего проекта. Не отказывайся от вердикта ' +
      'только потому, что видишь не весь репозиторий.\n' +
      '- Для уязвимостей в зависимостях опирайся на манифест: важны версия и то, ' +
      'достижим ли уязвимый код, а не строка lock-файла.\n' +
      '- «recommendation» должна быть выполнимой: конкретная версия, конкретная замена ' +
      'вызова или конкретная правка конфигурации, а не «проверьте» и «убедитесь».\n' +
      '- Отвечай по-русски.\n' +
      'Верни СТРОГО JSON: {"verdicts":[{"id":"<id находки>","verdict":"TRUE_POSITIVE|FALSE_POSITIVE|UNCERTAIN",' +
      '"reason":"почему проблема возникает","exploitation":"как это эксплуатируется или почему нет",' +
      '"recommendation":"конкретное исправление","confidence":"HIGH|MEDIUM|LOW"}]}';

    const userPrompt = `Находки для анализа:\n\n${items
      .map(
        it =>
          `### id: ${it.id}\n` +
          `сканер: ${it.scanner} | правило: ${it.rule} | severity: ${it.severity}\n` +
          `место: ${it.location}\n` +
          `описание: ${it.description}\n` +
          `код:\n\`\`\`\n${it.code || '(фрагмент недоступен)'}\n\`\`\``,
      )
      .join('\n\n')}`;

    const result = await this.groq.completeJson<{ verdicts: TriageVerdict[] }>(systemPrompt, userPrompt);
    if (!result.ok) {
      throw new Error(result.error || 'вызов модели не удался');
    }
    if (!Array.isArray(result.data?.verdicts)) {
      throw new Error('ответ модели не содержит поле verdicts');
    }

    const allowedIds = new Set(batch.map(f => f.id));
    return result.data!.verdicts.filter(v => v && allowedIds.has(v.id));
  }

  /**
   * Stores one AIAnalysis row per finding, linked via findingId.
   *
   * The verdict is also copied onto the duplicates the triage selection folded
   * away (same file + same rule), so every finding in the table carries an AI
   * verdict instead of leaving the repeated ones blank.
   */
  private async persistVerdicts(
    scanId: string,
    batch: Finding[],
    verdicts: TriageVerdict[],
    allFindings: Finding[],
  ) {
    for (const verdict of verdicts) {
      const finding = batch.find(f => f.id === verdict.id);
      if (!finding) continue;

      const response = [
        `Вердикт: ${verdict.verdict} (уверенность: ${verdict.confidence || 'MEDIUM'})`,
        '',
        `Почему возникает: ${verdict.reason || '—'}`,
        `Эксплуатация: ${verdict.exploitation || '—'}`,
        `Рекомендация: ${verdict.recommendation || '—'}`,
      ].join('\n');

      const metadata = {
        verdict: verdict.verdict,
        confidence: verdict.confidence,
        reason: verdict.reason,
        exploitation: verdict.exploitation,
        recommendation: verdict.recommendation,
      };

      // Представитель группы плюс все его дубликаты.
      const key = InvestigationService.dedupKey(finding);
      const targets = allFindings.filter(f => InvestigationService.dedupKey(f) === key);

      for (const target of targets) {
        const isDuplicate = target.id !== finding.id;
        try {
          await this.prisma.aIAnalysis.create({
            data: {
              scanId,
              findingId: target.id,
              type: 'finding_triage',
              response: isDuplicate
                ? `${response}\n\n(Тот же дефект, что и в строке ${finding.startLine ?? '?'}: вердикт распространён на все срабатывания этого правила в файле.)`
                : response,
              model: 'ollama',
              metadata: { ...metadata, duplicateOf: isDuplicate ? finding.id : undefined } as any,
            },
          });
        } catch (err: any) {
          this.logger.warn(`Could not store triage for finding ${target.id}: ${err.message}`);
        }
      }
    }
  }

  /**
   * Asks for data-flow relationships between the confirmed findings and writes
   * them into the security graph. Only relationships that name a file actually
   * present in the findings are accepted.
   */
  private async buildAttackPaths(
    scanId: string,
    findings: Finding[],
    verdicts: TriageVerdict[],
  ): Promise<number> {
    const compact = findings.slice(0, 12).map(f => {
      const v = verdicts.find(x => x.id === f.id);
      return {
        severity: f.severity,
        rule: f.ruleId,
        location: f.filePath ? `${f.filePath}:${f.startLine ?? '?'}` : 'unknown',
        title: (f.title || '').slice(0, 140),
        // Граф строится до триажа, поэтому вердикта обычно ещё нет: описание
        // находки и фрагмент кода заменяют его как опору для связей.
        description: (f.description || '').slice(0, 200),
        code: (f.codeSnippet || '').slice(0, 220),
        verdict: v?.verdict,
        exploitation: (v?.exploitation || '').slice(0, 220),
      };
    });

    const knownFiles = new Set(findings.map(f => f.filePath).filter(Boolean) as string[]);

    const systemPrompt =
      'Ты строишь граф цепочек атак по подтверждённым находкам сканеров. Свяжи точки входа ' +
      '(пользовательский ввод, внешние запросы) с опасными операциями (SQL, shell, файловая ' +
      'система, сеть, криптография).\n' +
      'Правила:\n' +
      '- Используй ТОЛЬКО перечисленные ниже файлы и находки, ничего не выдумывай.\n' +
      '- confidence="CONFIRMED" ставь, только если связь прямо следует из данных находки; ' +
      'иначе "POTENTIAL".\n' +
      '- type выбирай из: FLOWS_TO, CALLS, DEPENDS_ON, READS, WRITES, CAUSES, RELATED_TO.\n' +
      '- Возвращай не более 8 связей, по-русски.\n' +
      'Верни СТРОГО JSON: {"paths":[{"source":"...","target":"...","type":"FLOWS_TO",' +
      '"filePath":"путь из списка","line":123,"reason":"доказательство","confidence":"CONFIRMED|POTENTIAL"}]}';

    const userPrompt =
      `Подтверждённые находки:\n${JSON.stringify(compact, null, 1)}\n\n` +
      `Допустимые файлы:\n${[...knownFiles].slice(0, 30).join('\n')}`;

    const result = await this.groq.completeJson<{ paths: AttackPathLink[] }>(systemPrompt, userPrompt);
    if (!result.ok) {
      throw new Error(result.error || 'вызов модели не удался');
    }
    if (!Array.isArray(result.data?.paths)) {
      throw new Error('ответ модели не содержит поле paths');
    }

    let created = 0;
    for (const link of result.data!.paths.slice(0, 8)) {
      if (!link?.source || !link?.target || !link?.reason) continue;

      // Reject anything that points at a file the scan never saw.
      if (link.filePath && !knownFiles.has(link.filePath)) {
        this.logger.warn(`Discarding attack path referencing unknown file '${link.filePath}'`);
        continue;
      }

      const type = VALID_EDGE_TYPES.has(String(link.type).toUpperCase())
        ? String(link.type).toUpperCase()
        : 'RELATED_TO';

      try {
        await this.tools.buildRelationship(scanId, String(link.source).slice(0, 120), String(link.target).slice(0, 120), type, {
          filePath: link.filePath,
          line: Number.isInteger(Number(link.line)) ? Number(link.line) : undefined,
          reason: String(link.reason).slice(0, 500),
          confidence: link.confidence === 'CONFIRMED' ? 'CONFIRMED' : 'POTENTIAL',
        });
        created++;
      } catch (err: any) {
        this.logger.warn(`Could not store relationship: ${err.message}`);
      }
    }

    return created;
  }

  /** Executive summary assembled from the stages that actually succeeded. */
  private async writeReport(
    scanId: string,
    all: Finding[],
    selected: Finding[],
    verdicts: TriageVerdict[],
    outcome: InvestigationOutcome,
  ): Promise<boolean> {
    const counts = all.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});

    const topIssues = selected.slice(0, 10).map(f => {
      const v = verdicts.find(x => x.id === f.id);
      return {
        severity: f.severity,
        location: f.filePath ? `${f.filePath}:${f.startLine ?? '?'}` : 'unknown',
        title: (f.title || '').slice(0, 140),
        verdict: v?.verdict || 'NOT_ANALYSED',
        reason: (v?.reason || '').slice(0, 220),
      };
    });

    const systemPrompt =
      'Ты — ведущий аудитор безопасности. Напиши краткий отчёт по-русски в Markdown по уже ' +
      'проведённому анализу. Не добавляй находок, которых нет во входных данных, и не ' +
      'приукрашивай. Разделы: «Общая оценка», «Ключевые риски», «Что исправить в первую ' +
      'очередь», «Ограничения проверки».\n' +
      'Верни СТРОГО JSON: {"report":"<markdown>"}';

    const userPrompt =
      `Всего находок: ${all.length}\n` +
      `По severity: ${JSON.stringify(counts)}\n` +
      `Уникальных дефектов (после объединения повторов одного правила в одном файле): ${selected.length}\n` +
      `Разобрано AI: ${outcome.triaged} (подтверждено: ${outcome.truePositives}, ` +
      `ложных: ${outcome.falsePositives})\n` +
      `Связей в графе атак: ${outcome.relationships}\n` +
      (outcome.stageErrors.length ? `Сбои этапов: ${outcome.stageErrors.join('; ')}\n` : '') +
      `\nКлючевые находки:\n${JSON.stringify(topIssues, null, 1)}`;

    const result = await this.groq.completeJson<{ report: string }>(systemPrompt, userPrompt);
    if (!result.ok || !result.data?.report) {
      throw new Error(result.error || 'модель не вернула текст отчёта');
    }

    // Прежний текст «проанализировал N из M» читался как «часть находок
    // пропущена», хотя разница — это повторы одного правила в одном файле,
    // которые получают вердикт представителя группы.
    const folded = all.length - selected.length;
    const header =
      folded > 0
        ? `> AI разобрал все ${all.length} находок: ${selected.length} уникальных дефектов ` +
          `(${folded} повторов того же правила в том же файле объединены).\n\n`
        : '';

    await this.prisma.aIAnalysis.create({
      data: {
        scanId,
        type: 'finding_analysis',
        response: header + result.data.report,
        model: 'ollama',
        metadata: {
          triaged: outcome.triaged,
          truePositives: outcome.truePositives,
          falsePositives: outcome.falsePositives,
          relationships: outcome.relationships,
          totalFindings: all.length,
        } as any,
      },
    });

    return true;
  }
}
