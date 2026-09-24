import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

import { OllamaService } from '../ai/ollama.service.js';
import { PrismaService } from '../prisma/index.js';
import {
  CONTROL_DEFINITIONS,
  ControlDefinition,
  EVIDENCE_EXTENSIONS,
  EVIDENCE_IGNORED_DIRS,
} from './control-evidence.js';

/**
 * Assessment of the project's SECURITY FUNCTIONS, as opposed to its defects.
 *
 * A scanner answers "where is there a vulnerability". This answers "is the
 * control implemented at all, and is it implemented correctly" — authentication,
 * authorisation, secrets handling, input validation, crypto, sessions, audit
 * logging, transport security, configuration and dependency hygiene.
 *
 * The distinction matters: a repository with no authentication anywhere
 * produces zero scanner findings for it, yet the control is missing entirely.
 *
 * Method: signals are matched deterministically against the real workspace
 * first; the model then only judges evidence that was actually found, and a
 * control with no evidence is reported as MISSING rather than invented.
 */

export type ControlStatus = 'IMPLEMENTED' | 'PARTIAL' | 'MISSING' | 'NOT_APPLICABLE' | 'UNKNOWN';

interface EvidenceHit {
  filePath: string;
  line: number;
  snippet: string;
  label: string;
  positive: boolean;
}

interface ControlEvidence {
  definition: ControlDefinition;
  hits: EvidenceHit[];
  packagesFound: string[];
}

export interface ControlAssessment {
  control: string;
  title: string;
  status: ControlStatus;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  summary: string;
  risk: string | null;
  recommendation: string | null;
  evidence: Array<{ filePath: string; line: number; snippet: string; note: string }>;
}

export interface ControlsOutcome {
  assessed: number;
  implemented: number;
  partial: number;
  missing: number;
  notApplicable: number;
  errors: string[];
}

const MAX_HITS_PER_SIGNAL = 3;
const MAX_HITS_PER_CONTROL = 8;

/**
 * Сколько контролей оценивается за один запрос к модели.
 *
 * По одному запросу на контроль дневной бюджет токенов Groq заканчивался
 * ещё до разбора самих находок; пачка по три укладывается в лимит на запрос
 * и сокращает число вызовов примерно втрое.
 */
const CONTROL_BATCH_SIZE = 3;
const MAX_FILE_BYTES = 400 * 1024;
const BACKSLASH = /\\/g;

@Injectable()
export class SecurityControlsService {
  private readonly logger = new Logger(SecurityControlsService.name);

  constructor(
    private readonly groq: OllamaService,
    private readonly prisma: PrismaService,
  ) {}

  async assess(scanId: string, workspacePath: string): Promise<ControlsOutcome> {
    const outcome: ControlsOutcome = {
      assessed: 0, implemented: 0, partial: 0, missing: 0, notApplicable: 0, errors: [],
    };

    const { all: allFiles, readable: files } = await this.collectFiles(workspacePath);
    if (allFiles.length === 0) {
      outcome.errors.push('В рабочей области нет файлов для проверки контролей');
      return outcome;
    }

    const manifestPackages = await this.readManifestPackages(workspacePath);
    const hasWebSurface = await this.detectWebSurface(workspacePath, files, manifestPackages);

    const evidence = await this.collectEvidence(workspacePath, files, allFiles, manifestPackages);

    this.logger.log(
      `Scan ${scanId}: security controls — ${evidence.length} контролей, ` +
        `веб-поверхность: ${hasWebSurface ? 'есть' : 'нет'}`,
    );

    // Контроли, решаемые без модели: неприменимые и те, где признаков нет
    // вовсе. Они отсеиваются до обращения к Groq.
    const needsModel: ControlEvidence[] = [];

    for (const item of evidence) {
      // A control that needs an HTTP surface is not applicable to, say, a
      // library or a pile of shell scripts.
      if (item.definition.requiresWebSurface && !hasWebSurface) {
        await this.persist(scanId, {
          control: item.definition.key,
          title: item.definition.title,
          status: 'NOT_APPLICABLE',
          confidence: 'MEDIUM',
          summary: 'В репозитории не обнаружено HTTP-сервиса или обработчиков запросов, к которым применим этот контроль.',
          risk: null,
          recommendation: null,
          evidence: [],
        });
        outcome.assessed++;
        outcome.notApplicable++;
        continue;
      }

      if (item.hits.length === 0 && item.packagesFound.length === 0) {
        await this.persist(scanId, this.missingWithoutEvidence(item));
        outcome.assessed++;
        outcome.missing++;
        continue;
      }

      needsModel.push(item);
    }

    // Пачками, а не по одному запросу на контроль: десять отдельных вызовов
    // съедали дневной бюджет токенов ещё до разбора самих находок.
    for (let i = 0; i < needsModel.length; i += CONTROL_BATCH_SIZE) {
      const batch = needsModel.slice(i, i + CONTROL_BATCH_SIZE);

      let assessments: ControlAssessment[] = [];
      try {
        assessments = await this.judgeBatch(batch);
      } catch (err: any) {
        const msg = `${batch.map(b => b.definition.title).join(', ')}: ${err.message}`;
        this.logger.warn(`Control assessment failed — ${msg}`);
        outcome.errors.push(msg);
      }

      for (const item of batch) {
        const assessment =
          assessments.find(a => a.control === item.definition.key) || this.unknownAssessment(item);

        await this.persist(scanId, assessment).catch(() => {});
        outcome.assessed++;
        if (assessment.status === 'IMPLEMENTED') outcome.implemented++;
        else if (assessment.status === 'PARTIAL') outcome.partial++;
        else if (assessment.status === 'MISSING') outcome.missing++;
        else if (assessment.status === 'NOT_APPLICABLE') outcome.notApplicable++;
      }
    }

    this.logger.log(
      `Scan ${scanId}: controls done — implemented=${outcome.implemented} partial=${outcome.partial} ` +
        `missing=${outcome.missing} n/a=${outcome.notApplicable}`,
    );

    return outcome;
  }

  // ---------------------------------------------------------------- workspace

  /**
   * `all` feeds the path-based signals (a lock file or a committed key proves
   * its point by existing); `readable` is the subset worth grepping.
   */
  private async collectFiles(root: string): Promise<{ all: string[]; readable: string[] }> {
    const found: string[] = [];
    const all: string[] = [];

    const walk = async (dir: string, depth: number) => {
      if (depth > 8 || all.length >= 12000) return;
      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (all.length >= 12000) return;
        const full = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!EVIDENCE_IGNORED_DIRS.has(entry.name)) await walk(full, depth + 1);
        } else if (entry.isFile()) {
          all.push(full);
          const ext = path.extname(entry.name).toLowerCase();
          if (found.length < 4000 && (EVIDENCE_EXTENSIONS.has(ext) || entry.name.startsWith('.env'))) {
            found.push(full);
          }
        }
      }
    };

    await walk(root, 0);
    return { all, readable: found };
  }

  private async readManifestPackages(root: string): Promise<string[]> {
    const packages: string[] = [];

    try {
      const pkgRaw = await fs.readFile(path.join(root, 'package.json'), 'utf8');
      const pkg = JSON.parse(pkgRaw);
      packages.push(...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.devDependencies || {}));
    } catch { /* no node manifest */ }

    for (const name of ['requirements.txt', 'pyproject.toml', 'go.mod', 'Gemfile', 'composer.json']) {
      try {
        const raw = await fs.readFile(path.join(root, name), 'utf8');
        packages.push(...raw.split(/\r?\n/).map(l => l.trim().split(/[=<>~\s]/)[0]).filter(Boolean));
      } catch { /* not present */ }
    }

    return [...new Set(packages)];
  }

  /** Does this project actually serve HTTP requests? */
  private async detectWebSurface(root: string, files: string[], packages: string[]): Promise<boolean> {
    const webPackages = [
      'express', 'fastify', 'koa', 'hapi', '@nestjs/core', 'next', 'nuxt',
      'flask', 'django', 'fastapi', 'aiohttp', 'gin-gonic', 'spring-boot-starter-web', 'rails', 'laravel',
    ];
    if (packages.some(p => webPackages.some(w => p.toLowerCase().includes(w)))) return true;

    const routePattern =
      /\b(app|router)\.(get|post|put|patch|delete)\s*\(|@(Get|Post|Put|Patch|Delete|Controller)\s*\(|@app\.route|func\s+\w*Handler\s*\(/;

    // Cheap sample: enough to tell a web service from a library.
    for (const file of files.slice(0, 400)) {
      const content = await this.readFileSafe(file);
      if (content && routePattern.test(content)) return true;
    }

    return false;
  }

  private async readFileSafe(file: string): Promise<string | null> {
    try {
      const stat = await fs.stat(file);
      if (stat.size > MAX_FILE_BYTES) return null;
      return await fs.readFile(file, 'utf8');
    } catch {
      return null;
    }
  }

  // ---------------------------------------------------------------- evidence

  private async collectEvidence(
    root: string,
    files: string[],
    allFiles: string[],
    packages: string[],
  ): Promise<ControlEvidence[]> {
    const result: ControlEvidence[] = CONTROL_DEFINITIONS.map(definition => ({
      definition,
      hits: [],
      packagesFound: (definition.packages || []).filter(p =>
        packages.some(installed => installed.toLowerCase() === p.toLowerCase()),
      ),
    }));

    const perSignalCount = new Map<string, number>();

    // Path-based signals first: a lock file or a committed .env proves its point
    // by existing, and those files are often too large to read.
    const relPaths = allFiles.map(f => path.relative(root, f).replace(BACKSLASH, '/'));
    for (const entry of result) {
      for (const signal of entry.definition.fileSignals || []) {
        const match = relPaths.find(rel => signal.match.test(rel));
        if (!match) continue;
        entry.hits.push({
          filePath: match,
          line: 0,
          snippet: `(файл присутствует в репозитории)`,
          label: signal.label,
          positive: signal.positive,
        });
      }
    }

    for (const file of files) {
      const content = await this.readFileSafe(file);
      if (!content) continue;

      const relPath = path.relative(root, file).replace(/\\/g, '/');
      const lines = content.split(/\r?\n/);

      for (const entry of result) {
        if (entry.hits.length >= MAX_HITS_PER_CONTROL) continue;

        for (const signal of entry.definition.signals) {
          const key = `${entry.definition.key}::${signal.label}`;
          if ((perSignalCount.get(key) || 0) >= MAX_HITS_PER_SIGNAL) continue;

          // Line-oriented search keeps a precise file:line for the evidence.
          for (let i = 0; i < lines.length; i++) {
            if (!signal.pattern.test(lines[i])) continue;

            entry.hits.push({
              filePath: relPath,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 200),
              label: signal.label,
              positive: signal.positive,
            });
            perSignalCount.set(key, (perSignalCount.get(key) || 0) + 1);
            break; // one hit per signal per file is enough
          }

          if (entry.hits.length >= MAX_HITS_PER_CONTROL) break;
        }
      }
    }

    // "Манифест без lock-файла" имеет смысл только если lock-файла правда нет.
    for (const entry of result) {
      const hasLock = entry.hits.some(h => h.label === 'Lock-файл зависимостей');
      if (hasLock) {
        entry.hits = entry.hits.filter(h => h.label !== 'Манифест зависимостей без lock-файла');
      }
    }

    return result;
  }

  // ------------------------------------------------------------------ verdict

  /** Вывод без обращения к модели: признаков контроля нет вообще. */
  private missingWithoutEvidence(item: ControlEvidence): ControlAssessment {
    return {
      control: item.definition.key,
      title: item.definition.title,
      status: 'MISSING',
      confidence: 'MEDIUM',
      summary:
        'В коде не найдено ни одного признака этого контроля: ни соответствующих библиотек, ' +
        'ни характерных вызовов. Контроль, судя по всему, не реализован.',
      risk: item.definition.risk,
      recommendation: 'Реализовать контроль либо явно обосновать, почему он не требуется для этого проекта.',
      evidence: [],
    };
  }

  /** Контроль не удалось оценить — это фиксируется, а не замалчивается. */
  private unknownAssessment(item: ControlEvidence): ControlAssessment {
    return {
      control: item.definition.key,
      title: item.definition.title,
      status: 'UNKNOWN',
      confidence: 'LOW',
      summary: 'Оценку выполнить не удалось: модель не вернула результат по этому контролю.',
      risk: item.definition.risk,
      recommendation: null,
      evidence: item.hits.slice(0, 3).map(h => ({
        filePath: h.filePath, line: h.line, snippet: h.snippet, note: h.label,
      })),
    };
  }

  /**
   * Judges several controls in a single model call.
   *
   * One call per control exhausted the daily token budget before the findings
   * themselves were analysed, so related controls are judged together; the
   * per-control evidence and validation stay exactly the same.
   */
  private async judgeBatch(batch: ControlEvidence[]): Promise<ControlAssessment[]> {
    const renderHits = (list: EvidenceHit[]) =>
      list.length
        ? list.map(h => `- [${h.label}] ${h.filePath}:${h.line}\n    ${h.snippet}`).join('\n')
        : '(не найдено)';

    const systemPrompt =
      'Ты — аудитор информационной безопасности. Тебе дают НЕСКОЛЬКО контролей безопасности и ' +
      'найденные в репозитории признаки их наличия или нарушения — с реальными строками кода.\n' +
      'Оцени КАЖДЫЙ контроль отдельно, опираясь ТОЛЬКО на показанные для него признаки.\n' +
      'Статусы:\n' +
      '- IMPLEMENTED — контроль реализован и признаков нарушения нет;\n' +
      '- PARTIAL — реализован частично либо есть и правильные, и опасные места;\n' +
      '- MISSING — признаков реализации нет, либо найденное прямо ей противоречит;\n' +
      '- NOT_APPLICABLE — контроль к такому проекту неприменим.\n' +
      'Правила:\n' +
      '- Не придумывай файлы и строки: в evidenceNotes можно ссылаться только на показанные.\n' +
      '- summary — 1–3 предложения по-русски, конкретно, со ссылкой на найденное.\n' +
      '- recommendation — что именно сделать, по-русски.\n' +
      '- Верни запись для каждого контроля из списка, с его точным "control".\n' +
      'Верни СТРОГО JSON: {"controls":[{"control":"<ключ>","status":"...",' +
      '"confidence":"HIGH|MEDIUM|LOW","summary":"...","recommendation":"...",' +
      '"evidenceNotes":[{"filePath":"...","line":1,"note":"..."}]}]}';

    const userPrompt = batch
      .map(item => {
        const positives = item.hits.filter(h => h.positive);
        const negatives = item.hits.filter(h => !h.positive);
        return (
          `### control: ${item.definition.key}\n` +
          `КОНТРОЛЬ: ${item.definition.title}\n` +
          `ВОПРОС: ${item.definition.question}\n` +
          `РИСК ПРИ ОТСУТСТВИИ: ${item.definition.risk}\n` +
          `Библиотеки в манифесте: ${item.packagesFound.join(', ') || '(нет)'}\n` +
          `ПРИЗНАКИ РЕАЛИЗАЦИИ:\n${renderHits(positives)}\n` +
          `ПРИЗНАКИ НАРУШЕНИЯ:\n${renderHits(negatives)}`
        );
      })
      .join('\n\n');

    const result = await this.groq.completeJson<{
      controls: Array<{
        control: string;
        status: string;
        confidence: string;
        summary: string;
        recommendation: string;
        evidenceNotes?: Array<{ filePath: string; line: number; note: string }>;
      }>;
    }>(systemPrompt, userPrompt);

    if (!result.ok || !Array.isArray(result.data?.controls)) {
      throw new Error(result.error || 'модель не вернула оценки контролей');
    }

    const assessments: ControlAssessment[] = [];

    for (const item of batch) {
      const answer = result.data!.controls.find(c => c?.control === item.definition.key);
      if (!answer) continue;

      assessments.push(this.toAssessment(item, answer));
    }

    return assessments;
  }

  /** Normalises a model answer and keeps only evidence pointing at real lines. */
  private toAssessment(
    item: ControlEvidence,
    answer: { status: string; confidence: string; summary: string; recommendation: string; evidenceNotes?: Array<{ filePath: string; line: number; note: string }> },
  ): ControlAssessment {
    const { definition, hits } = item;

    const allowed: ControlStatus[] = ['IMPLEMENTED', 'PARTIAL', 'MISSING', 'NOT_APPLICABLE', 'UNKNOWN'];
    const status = allowed.includes(String(answer.status).toUpperCase() as ControlStatus)
      ? (String(answer.status).toUpperCase() as ControlStatus)
      : 'UNKNOWN';

    const confidence = ['HIGH', 'MEDIUM', 'LOW'].includes(String(answer.confidence).toUpperCase())
      ? (String(answer.confidence).toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW')
      : 'MEDIUM';

    const known = new Map(hits.map(h => [`${h.filePath}:${h.line}`, h]));
    const notes = (answer.evidenceNotes || [])
      .map(n => {
        const hit = known.get(`${n.filePath}:${n.line}`);
        if (!hit) return null;
        return { filePath: hit.filePath, line: hit.line, snippet: hit.snippet, note: String(n.note || hit.label).slice(0, 300) };
      })
      .filter(Boolean) as ControlAssessment['evidence'];

    const evidence = notes.length
      ? notes
      : hits.slice(0, 5).map(h => ({ filePath: h.filePath, line: h.line, snippet: h.snippet, note: h.label }));

    return {
      control: definition.key,
      title: definition.title,
      status,
      confidence,
      summary: String(answer.summary || '').slice(0, 600) || 'Модель не дала пояснения.',
      risk: status === 'IMPLEMENTED' ? null : definition.risk,
      recommendation: answer.recommendation ? String(answer.recommendation).slice(0, 600) : null,
      evidence,
    };
  }


  private async persist(scanId: string, assessment: ControlAssessment) {
    await this.prisma.securityControl.upsert({
      where: { scanId_control: { scanId, control: assessment.control } },
      create: {
        scanId,
        control: assessment.control,
        title: assessment.title,
        status: assessment.status as any,
        confidence: assessment.confidence as any,
        summary: assessment.summary,
        risk: assessment.risk,
        recommendation: assessment.recommendation,
        evidence: assessment.evidence as any,
      },
      update: {
        title: assessment.title,
        status: assessment.status as any,
        confidence: assessment.confidence as any,
        summary: assessment.summary,
        risk: assessment.risk,
        recommendation: assessment.recommendation,
        evidence: assessment.evidence as any,
      },
    });
  }
}
