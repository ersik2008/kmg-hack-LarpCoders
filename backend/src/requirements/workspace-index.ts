import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Индекс рабочей области для проверки Требований ИБ.
 *
 * Зачем отдельный индекс, если уже есть сборщик признаков контролей: тот читает
 * только исходный код и конфигурацию. Требование ИБ-06 проверяется по
 * документации, а `.md` не входил ни в один список читаемых расширений — то
 * есть документация не читалась ни одним компонентом анализа вообще.
 *
 * Индекс строится один раз на скан и переиспользуется всеми проверками
 * требований, поэтому рабочая область обходится однократно, а не восемь раз.
 */

export type FileKind =
  | 'source'       // исходный код
  | 'config'       // конфигурация приложения и инфраструктуры
  | 'docs'         // документация: README, docs/, спецификации
  | 'manifest'     // описание зависимостей
  | 'ci'           // конфигурация CI/CD
  | 'webserver'    // конфигурация веб-сервера и обратного прокси
  | 'migration'    // миграции БД
  | 'test'         // тесты и фикстуры
  | 'other';

export interface IndexedFile {
  /** Путь относительно корня рабочей области, всегда через `/`. */
  relPath: string;
  absPath: string;
  kind: FileKind;
  ext: string;
  size: number;
  /** Файл относится к слою, исполняемому на сервере. */
  serverSide: boolean;
  /** Файл относится к клиентскому коду (браузер). */
  clientSide: boolean;
}

export interface Hit {
  filePath: string;
  line: number;
  /** Текст строки, обрезанный до разумной длины. */
  text: string;
  kind: FileKind;
}

export interface GrepOptions {
  /**
   * По умолчанию комментарии, строки-литералы и файлы-таблицы правил в поиск
   * не попадают: закомментированный guard защитой не является, а строка вида
   * `'verify=False'` в описании детектора — не отключённая проверка сертификата.
   * Флаг нужен только проверке документации.
   */
  includeNoise?: boolean;
  /** Ограничить поиск этими категориями файлов. */
  kinds?: FileKind[];
  /** Ограничить поиск файлами, чей путь соответствует выражению. */
  pathPattern?: RegExp;
  /** Только серверный код. */
  serverOnly?: boolean;
  /** Исключить тесты и фикстуры: там намеренно лежит небезопасный код. */
  excludeTests?: boolean;
  /** Максимум попаданий (по умолчанию 40). */
  limit?: number;
  /** Максимум попаданий на один файл (по умолчанию 3). */
  perFile?: number;
}

const IGNORED_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', '.next', 'out', 'coverage',
  '.cache', 'vendor', '__pycache__', '.venv', 'venv', '.idea', '.vscode',
  'target', 'bin', 'obj', '.turbo', '.pytest_cache', '.mypy_cache',
]);

const SOURCE_EXT = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.go', '.java', '.rb',
  '.php', '.cs', '.kt', '.scala', '.swift', '.rs', '.c', '.cc', '.cpp', '.h',
  '.hpp', '.vue', '.svelte',
]);

/**
 * Документация. Ровно ради этого набора индекс и появился: без чтения `.md`
 * требование ИБ-06 (ссылки на нормативную базу) проверить нечем в принципе.
 */
const DOCS_EXT = new Set(['.md', '.markdown', '.rst', '.adoc', '.asciidoc', '.txt']);

const CONFIG_EXT = new Set(['.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.properties', '.env', '.conf']);

const MANIFEST_NAMES = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'pyproject.toml', 'poetry.lock', 'pipfile', 'pipfile.lock',
  'go.mod', 'go.sum', 'gemfile', 'gemfile.lock', 'composer.json', 'composer.lock',
  'cargo.toml', 'cargo.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
]);

const WEBSERVER_PATTERNS = [
  /(^|\/)nginx[^/]*\.conf$/i,
  /(^|\/)nginx\//i,
  /(^|\/)httpd\.conf$/i,
  /(^|\/)apache2?\.conf$/i,
  /(^|\/)\.htaccess$/i,
  /(^|\/)Caddyfile$/i,
  /(^|\/)traefik[^/]*\.(ya?ml|toml)$/i,
  /(^|\/)haproxy\.cfg$/i,
];

const CI_PATTERNS = [
  /(^|\/)\.github\/workflows\//i,
  /(^|\/)\.gitlab-ci\.ya?ml$/i,
  /(^|\/)Jenkinsfile$/i,
  /(^|\/)azure-pipelines\.ya?ml$/i,
  /(^|\/)\.circleci\//i,
  /(^|\/)bitbucket-pipelines\.ya?ml$/i,
];

const MIGRATION_PATTERNS = [
  /(^|\/)migrations?\//i,
  /(^|\/)db\/migrate\//i,
  /(^|\/)alembic\//i,
  /\.sql$/i,
];

const TEST_PATTERNS = [
  /(^|\/)(tests?|__tests__|spec|e2e|fixtures?|testdata|mocks?)\//i,
  /\.(test|spec)\.[a-z]+$/i,
  /(^|\/)conftest\.py$/i,
  /(^|\/)security-test-repository\//i,
];

/** Каталоги и файлы, однозначно относящиеся к клиентскому коду. */
const CLIENT_PATTERNS = [
  /(^|\/)(frontend|client|web|ui|public|static|assets)\//i,
  /\.(jsx|tsx|vue|svelte)$/i,
  /(^|\/)(pages|components|views|hooks|store)\//i,
];

/** Каталоги, однозначно относящиеся к серверному коду. */
const SERVER_PATTERNS = [
  /(^|\/)(backend|server|api|src\/main|app|services?|controllers?|routes?|handlers?|middleware)\//i,
  /(^|\/)(main|app|server|index)\.(ts|js|py|go|java|rb)$/i,
];

/** Комментарий в исходнике, конфигурации, nginx, YAML, SQL. */
const COMMENT_LINE = /^\s*(?:\/\/|#|\*(?!\w)|\/\*|<!--|--\s|;\s)/;

/**
 * Строка, состоящая из литерала: продолжение многострочной строки или элемент
 * массива строк. В JSON/YAML такие строки — обычная конфигурация, поэтому
 * правило действует только для исходного кода.
 */
const STRING_LITERAL_LINE = /^\s*['"`][^'"`]*['"`]\s*(?:\+|,)?\s*$|^\s*['"`].*['"`]\s*\+\s*$/;

/** Описание шаблона: `pattern: /.../`, `label: '...'`. */
const PATTERN_DEFINITION_LINE = /\b(?:pattern|patterns|regex|match)\s*:\s*(?:\/|RegExp|\[)|\bnew\s+RegExp\s*\(|\bpattern\s*:\s*RegExp\b/;

/** Константа-регулярное выражение целиком: `const X = /.../flags;`. */
const REGEX_CONSTANT_LINE = /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*(?::[^=]+)?=\s*\/(?![\/*]).*\/[gimsuy]*\s*;?\s*$/;

const MAX_FILES = 20_000;
const MAX_DEPTH = 12;
const MAX_READ_BYTES = 1024 * 1024;

export class WorkspaceIndex {
  private readonly contents = new Map<string, string[] | null>();
  private readonly ruleTables = new Map<string, boolean>();

  private constructor(
    readonly root: string,
    readonly files: IndexedFile[],
  ) {}

  static async build(root: string): Promise<WorkspaceIndex> {
    const files: IndexedFile[] = [];
    await walk(root, root, 0, files);
    return new WorkspaceIndex(root, files);
  }

  get fileCount(): number {
    return this.files.length;
  }

  byKind(...kinds: FileKind[]): IndexedFile[] {
    const set = new Set(kinds);
    return this.files.filter(f => set.has(f.kind));
  }

  /** Есть ли в проекте HTTP-поверхность — от этого зависит применимость ИБ-01…ИБ-03. */
  async hasWebSurface(): Promise<boolean> {
    const manifests = this.byKind('manifest');
    const webPackages = /\b(express|fastify|koa|hapi|@nestjs\/core|next|nuxt|flask|django|fastapi|aiohttp|starlette|gin-gonic|spring-boot-starter-web|rails|laravel|actix-web|axum)\b/i;

    for (const m of manifests.slice(0, 20)) {
      const text = (await this.read(m.relPath))?.join('\n') ?? '';
      if (webPackages.test(text)) return true;
    }

    const routes = await this.grep(
      /\b(app|router)\.(get|post|put|patch|delete)\s*\(|@(Get|Post|Put|Patch|Delete|Controller)\s*\(|@app\.route|@router\.(get|post)|func\s+\w*Handler\s*\(|http\.HandleFunc/,
      { kinds: ['source'], limit: 1, excludeTests: true },
    );
    return routes.length > 0;
  }

  /**
   * Строки файла с ПУСТЫМИ строками на месте комментариев.
   *
   * Проверки, которые смотрят «окрестность» найденного места (guard выше
   * маршрута, аудит рядом с выгрузкой), обязаны читать код, а не комментарии:
   * закомментированный `// router.use(requireAdmin)` защитой не является.
   * Нумерация строк сохраняется, поэтому `file:line` в отчёте остаётся точным.
   */
  async readCode(relPath: string): Promise<string[] | null> {
    const lines = await this.read(relPath);
    if (!lines) return null;
    const file = this.files.find(f => f.relPath === relPath);
    if (!file || file.kind === 'docs' || file.kind === 'manifest') return lines;
    return lines.map(l => (COMMENT_LINE.test(l) ? '' : l));
  }

  /**
   * Файл — таблица правил или детекторов: сотни строк, описывающих
   * анти-паттерны как данные. Такой файл сам по себе ничего не реализует и ни
   * от чего не защищает; учитывать его совпадения — значит ловить собственные
   * описания уязвимостей (тот же класс, что тестовые фикстуры).
   */
  async isRuleTable(relPath: string): Promise<boolean> {
    const cached = this.ruleTables.get(relPath);
    if (cached !== undefined) return cached;

    const lines = await this.read(relPath);
    let result = false;
    if (lines) {
      let defs = 0;
      for (const line of lines) {
        if (PATTERN_DEFINITION_LINE.test(line) || REGEX_CONSTANT_LINE.test(line)) defs++;
        if (defs >= 3) { result = true; break; }
      }
      // Правила Semgrep в YAML: `rules:` + `- id:` + `message:`.
      if (!result) {
        const text = lines.join(String.fromCharCode(10));
        result = /^rules:\s*$/m.test(text) && /^\s*-\s*id:/m.test(text) && /^\s*message:/m.test(text);
      }
    }
    this.ruleTables.set(relPath, result);
    return result;
  }

  /** Читает файл построчно. Результат кешируется на время жизни индекса. */
  async read(relPath: string): Promise<string[] | null> {
    if (this.contents.has(relPath)) return this.contents.get(relPath) ?? null;

    const file = this.files.find(f => f.relPath === relPath);
    if (!file || file.size > MAX_READ_BYTES) {
      this.contents.set(relPath, null);
      return null;
    }

    try {
      const raw = await fs.readFile(file.absPath, 'utf8');
      const lines = raw.split(/\r?\n/);
      this.contents.set(relPath, lines);
      return lines;
    } catch {
      this.contents.set(relPath, null);
      return null;
    }
  }

  /**
   * Построчный поиск по индексу.
   *
   * Возвращает именно `file:line:text`, а не булево «нашлось»: любой вывод о
   * требовании должен опираться на конкретное место в проекте (ТЗ п. 4.6.4).
   */
  async grep(pattern: RegExp, options: GrepOptions = {}): Promise<Hit[]> {
    const {
      kinds, pathPattern, serverOnly = false, excludeTests = false,
      limit = 40, perFile = 3,
    } = options;

    const kindSet = kinds ? new Set(kinds) : null;
    const hits: Hit[] = [];

    for (const file of this.files) {
      if (hits.length >= limit) break;
      if (kindSet && !kindSet.has(file.kind)) continue;
      if (pathPattern && !pathPattern.test(file.relPath)) continue;
      if (serverOnly && !file.serverSide) continue;
      if (excludeTests && file.kind === 'test') continue;

      const lines = await this.read(file.relPath);
      if (!lines) continue;

      const filterNoise = !options.includeNoise && file.kind !== 'docs' && file.kind !== 'manifest';
      if (filterNoise && (await this.isRuleTable(file.relPath))) continue;

      let inFile = 0;
      for (let i = 0; i < lines.length && inFile < perFile && hits.length < limit; i++) {
        if (filterNoise) {
          const line = lines[i];
          if (COMMENT_LINE.test(line)) continue;
          if (file.kind === 'source' && STRING_LITERAL_LINE.test(line)) continue;
        }

        // `lastIndex` у глобальных выражений тянется между вызовами и пропускает
        // совпадения, поэтому поиск всегда идёт с нуля.
        pattern.lastIndex = 0;
        if (!pattern.test(lines[i])) continue;

        hits.push({
          filePath: file.relPath,
          line: i + 1,
          text: lines[i].trim().slice(0, 240),
          kind: file.kind,
        });
        inFile++;
      }
    }

    return hits;
  }

  /** Существует ли в проекте файл, соответствующий выражению. */
  findPath(pattern: RegExp): IndexedFile | undefined {
    return this.files.find(f => pattern.test(f.relPath));
  }

  findAllPaths(pattern: RegExp): IndexedFile[] {
    return this.files.filter(f => pattern.test(f.relPath));
  }
}

async function walk(root: string, dir: string, depth: number, out: IndexedFile[]): Promise<void> {
  if (depth > MAX_DEPTH || out.length >= MAX_FILES) return;

  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (out.length >= MAX_FILES) return;
    const abs = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) await walk(root, abs, depth + 1, out);
      continue;
    }
    if (!entry.isFile()) continue;

    let size = 0;
    try {
      size = (await fs.stat(abs)).size;
    } catch {
      continue;
    }

    const relPath = path.relative(root, abs).replace(/\\/g, '/');
    out.push({
      relPath,
      absPath: abs,
      kind: classify(relPath, entry.name),
      ext: path.extname(entry.name).toLowerCase(),
      size,
      serverSide: isServerSide(relPath),
      clientSide: CLIENT_PATTERNS.some(p => p.test(relPath)),
    });
  }
}

function classify(relPath: string, name: string): FileKind {
  const lower = name.toLowerCase();
  const ext = path.extname(lower);

  // Тесты проверяются раньше остального: в тестовой фикстуре намеренно лежит
  // небезопасный код, и принимать его за продакшн-реализацию нельзя.
  if (TEST_PATTERNS.some(p => p.test(relPath))) return 'test';
  if (CI_PATTERNS.some(p => p.test(relPath))) return 'ci';
  if (WEBSERVER_PATTERNS.some(p => p.test(relPath))) return 'webserver';
  if (MIGRATION_PATTERNS.some(p => p.test(relPath))) return 'migration';
  if (MANIFEST_NAMES.has(lower)) return 'manifest';
  if (DOCS_EXT.has(ext)) return 'docs';
  if (SOURCE_EXT.has(ext)) return 'source';
  if (CONFIG_EXT.has(ext) || lower.startsWith('.env') || lower === 'dockerfile' || lower.startsWith('docker-compose')) {
    return 'config';
  }
  return 'other';
}

function isServerSide(relPath: string): boolean {
  if (CLIENT_PATTERNS.some(p => p.test(relPath))) return false;
  return SERVER_PATTERNS.some(p => p.test(relPath));
}
