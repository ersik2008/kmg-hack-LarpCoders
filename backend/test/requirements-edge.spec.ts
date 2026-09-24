import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { RequirementsService } from '../src/requirements/requirements.service.js';
import type { RequirementResult } from '../src/requirements/requirement-definitions.js';

/**
 * Защита от ложных срабатываний (постановка, п. 22) и граничные случаи.
 *
 * Каждый тест — маленький проект, собранный во временном каталоге. Проверяется
 * не «что-то нашлось», а точный статус конкретного требования.
 */

const service = new RequirementsService({} as any);
const created: string[] = [];

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kmg-req-'));
  created.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

async function evaluate(files: Record<string, string>) {
  const outcome = await service.evaluate(project(files), 'edge');
  const by = new Map<string, RequirementResult>(outcome.results.map(r => [r.requirementId, r]));
  return { outcome, get: (id: string) => by.get(id)! };
}

afterAll(() => {
  for (const dir of created) fs.rmSync(dir, { recursive: true, force: true });
});

const EXPRESS = JSON.stringify({ dependencies: { express: '^4' } });

describe('Применимость: NOT_APPLICABLE, а не PASS', () => {
  it('библиотека без HTTP-поверхности: ИБ-01/02/03/08 неприменимы', async () => {
    const { get } = await evaluate({
      'package.json': JSON.stringify({ name: 'lib', dependencies: { lodash: '^4' } }),
      'src/index.ts': 'export const add = (a: number, b: number) => a + b;',
    });
    for (const id of ['ИБ-01', 'ИБ-02', 'ИБ-03', 'ИБ-08']) {
      expect(get(id).status, id).toBe('NOT_APPLICABLE');
    }
  });

  it('пустой проект не даёт результатов, а не восемь PASS', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kmg-empty-'));
    created.push(dir);
    const outcome = await service.evaluate(dir, 'empty');
    expect(outcome.results).toEqual([]);
    expect(outcome.errors.join(' ')).toMatch(/пуст/);
  });
});

describe('Ложные срабатывания: контекст важнее совпадения', () => {
  it('ИБ-03: http://localhost в dev-конфигурации не нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/config.dev.ts': "export const API = 'http://localhost:3000';",
      'src/server.ts': "import https from 'https'; https.createServer({ key, cert, minVersion: 'TLSv1.2' }, app);",
    });
    expect(get('ИБ-03').status).not.toBe('VIOLATION');
  });

  it('ИБ-03: http:// внутри комментария и пространства имён XML — не эндпоинт', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/a.ts': "// see http://example.com/docs\nconst ns = 'http://www.w3.org/2000/svg';",
      'src/server.ts': "https.createServer({ key, cert, minVersion: 'TLSv1.2' }, app);",
    });
    expect(get('ИБ-03').status).not.toBe('VIOLATION');
  });

  it('ИБ-03: http:// в продакшн-конфигурации — нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/config.prod.ts': "export const API = 'http://api.company.example';",
    });
    expect(get('ИБ-03').status).toBe('VIOLATION');
  });

  it('ИБ-03: listen 80 с перенаправлением на HTTPS — не нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'deploy/nginx.conf':
        'server { listen 80; return 301 https://$host$request_uri; }\n' +
        'server { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; ssl_certificate a; }',
    });
    expect(get('ИБ-03').status).toBe('PASS');
  });

  it('ИБ-03: listen 80 без перенаправления — нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'deploy/nginx.conf': 'server { listen 80; location / { proxy_pass http://app; } }',
    });
    expect(get('ИБ-03').status).toBe('VIOLATION');
  });

  it('ИБ-03: rejectUnauthorized:false в тестовом файле — не нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/server.ts': "https.createServer({ key, cert, minVersion: 'TLSv1.2' }, app);",
      'test/tls.spec.ts': 'const agent = { rejectUnauthorized: false };',
    });
    expect(get('ИБ-03').status).not.toBe('VIOLATION');
  });

  it('ИБ-04: SHA-256 как контрольная сумма файла — не хеш пароля', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/files.ts': "const etag = createHash('sha256').update(fileBuffer).digest('hex'); // checksum",
      'src/auth.ts': "import argon2 from 'argon2'; export const h = (p: string) => argon2.hash(p);",
    });
    expect(get('ИБ-04').violations.filter(v => /sha256/i.test(v.evidence))).toEqual([]);
    expect(get('ИБ-04').status).not.toBe('VIOLATION');
  });

  it('ИБ-04: SHA-512 для пароля — нарушение (не только md5/sha1)', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/auth.ts': "export const hashPassword = (password: string) => createHash('sha512').update(password).digest('hex');",
    });
    expect(get('ИБ-04').status).toBe('VIOLATION');
  });

  it('ИБ-04: поле password в DTO и bcrypt.hash — не открытый текст', async () => {
    const { get } = await evaluate({
      'package.json': JSON.stringify({ dependencies: { express: '^4', bcrypt: '^5' } }),
      'src/dto.ts': 'export class LoginDto { password!: string; }',
      'src/auth.ts': "import bcrypt from 'bcrypt'; export const h = (password: string) => bcrypt.hash(password, 12);",
    });
    expect(get('ИБ-04').status).toBe('PASS');
  });

  it('ИБ-04: AES-256-CBC сам по себе не нарушение (ТЗ не запрещает режим)', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/crypto.ts': "createCipheriv('aes-256-cbc', key, iv);",
      'src/auth.ts': "import argon2 from 'argon2'; export const h = (p: string) => argon2.hash(p);",
    });
    expect(get('ИБ-04').status).toBe('PASS');
  });

  it('ИБ-04: ECB — нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/crypto.ts': "createCipheriv('aes-128-ecb', key, null);",
    });
    expect(get('ИБ-04').status).toBe('VIOLATION');
  });

  it('закомментированная защита защитой не считается', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/routes.ts':
        "// router.use(requireAdmin);\n" +
        "router.get('/admin/users', (req, res) => res.json([]));",
    });
    expect(get('ИБ-01').status).toBe('VIOLATION');
  });

  it('строка-описание в таблице правил не считается кодом', async () => {
    const rules = [
      "const RULES = [",
      "  { label: 'md5', pattern: /createHash\\('md5'\\).*password/i },",
      "  { label: 'ecb', pattern: /aes-128-ecb/i },",
      "  { label: 'tls', pattern: /rejectUnauthorized\\s*:\\s*false/ },",
      "];",
    ].join('\n');
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/detector-rules.ts': rules,
    });
    expect(get('ИБ-04').status).not.toBe('VIOLATION');
    expect(get('ИБ-03').status).not.toBe('VIOLATION');
  });
});

describe('ИБ-01: серверная проверка, а не сокрытие в интерфейсе', () => {
  it('роль проверяется только на клиенте → нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'frontend/src/Menu.tsx': "export const Menu = ({ user }) => user.role === 'admin' && <AdminLink />;",
      'server/routes.ts': "router.get('/admin/users', (req, res) => res.json(users));",
    });
    const r = get('ИБ-01');
    expect(r.status).toBe('VIOLATION');
    expect(r.violations[0].explanation).toMatch(/клиентск/);
  });

  it('guard на роутере покрывает маршруты файла', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/admin.ts':
        "router.use(requireAdmin);\n" +
        "router.get('/admin/users', (req, res) => res.json([]));\n" +
        "router.delete('/admin/users/:id', (req, res) => res.sendStatus(204));",
    });
    expect(get('ИБ-01').status).toBe('PASS');
  });

  it('глобальный guard ролей покрывает все маршруты', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/main.ts': 'providers: [{ provide: APP_GUARD, useClass: RolesGuard }]',
      'server/admin.ts': "router.get('/admin/users', (req, res) => res.json([]));",
    });
    expect(get('ИБ-01').status).toBe('PASS');
  });

  it('маршрутизатор с предметным именем (adminRouter) распознаётся', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/admin.ts': "adminRouter.get('/admin/users', (req, res) => res.json([]));",
    });
    expect(get('ИБ-01').status).toBe('VIOLATION');
  });

  it('исходящий HTTP-вызов axios.get не принимается за маршрут', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/client.ts': "await axios.get('/admin/stats');",
    });
    expect(get('ИБ-01').status).not.toBe('VIOLATION');
  });
});

describe('ИБ-02: серверная проверка токена', () => {
  it('jwt.decode без verify — нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/auth.ts': "const claims = jwt.decode(token); req.user = claims;",
    });
    expect(get('ИБ-02').status).toBe('VIOLATION');
  });

  it('глобальный auth-middleware и публичные маршруты — PASS', async () => {
    const { get } = await evaluate({
      'package.json': JSON.stringify({ dependencies: { express: '^4', jsonwebtoken: '^9' } }),
      'server/main.ts': 'app.use(authMiddleware);',
      'server/auth.ts': "export const authMiddleware = (req, res, next) => { req.user = jwt.verify(t, s, { algorithms: ['HS256'] }); next(); };",
      'server/routes.ts': "router.get('/orders', h);\nrouter.get('/health', h);\nrouter.post('/login', h);",
    });
    expect(get('ИБ-02').status).toBe('PASS');
  });

  it('публичные маршруты (health/login/webhook) не считаются незащищёнными', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/routes.ts': "router.use(authGuard);\nrouter.get('/health', h);\nrouter.post('/login', h);\nrouter.post('/webhook', h);",
    });
    expect(get('ИБ-02').violations.filter(v => /health|login|webhook/.test(String(v.symbol)))).toEqual([]);
  });

  it('FastAPI: маршрут с Depends(проверка) защищён, без неё — нет', async () => {
    const protectedApp = await evaluate({
      'requirements.txt': 'fastapi\nuvicorn\n',
      'app/main.py':
        'from fastapi import FastAPI, Depends\n' +
        'def require_token(x_token: str = Header()): ...\n' +
        '@app.post("/scan", dependencies=[Depends(require_token)])\n' +
        'async def scan(): ...\n',
    });
    expect(protectedApp.get('ИБ-02').status).toBe('PASS');

    const open = await evaluate({
      'requirements.txt': 'fastapi\nuvicorn\n',
      'app/main.py': '@app.post("/scan")\nasync def scan(): ...\n',
    });
    expect(open.get('ИБ-02').status).toBe('VIOLATION');
  });

  it('токен без срока жизни — нарушение', async () => {
    const { get } = await evaluate({
      'package.json': JSON.stringify({ dependencies: { express: '^4', jsonwebtoken: '^9' } }),
      'server/main.ts': 'app.use(authMiddleware);',
      'server/auth.ts': "export const authMiddleware = (r, s, n) => { jwt.verify(t, k, { algorithms: ['HS256'] }); n(); };\nexport const issue = (id) => jwt.sign({ id }, k);",
    });
    expect(get('ИБ-02').violations.some(v => v.symbol === 'срок жизни токена')).toBe(true);
  });
});

describe('ИБ-05: локальный журнал', () => {
  it('приложение пишет только в stdout → неприменимо, а не нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/log.ts': "import pino from 'pino'; export const logger = pino();",
    });
    expect(get('ИБ-05').status).toBe('NOT_APPLICABLE');
  });

  it('файловый журнал без шифрования → нарушение', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/logger.ts': "new winston.transports.File({ filename: 'app.log' });",
    });
    expect(get('ИБ-05').status).toBe('VIOLATION');
  });

  it('шифрование в несвязанном модуле не защищает журнал', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/logger.ts': "new winston.transports.File({ filename: 'app.log' });",
      'src/tokens.ts': "createCipheriv('aes-256-gcm', k, iv); createHmac('sha256', k);",
    });
    expect(get('ИБ-05').status).toBe('VIOLATION');
  });

  it('type: "file" (узел дерева файлов) не принимается за файловый журнал', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/tree.ts': "const node = { name: 'a', type: 'file' };",
    });
    expect(get('ИБ-05').status).toBe('NOT_APPLICABLE');
  });
});

describe('ИБ-06: ссылки на нормативную базу', () => {
  const ALL = [
    'Закон РК № 418-V «О кибербезопасности»',
    'Закон РК № 94-V «О персональных данных и их защите»',
    'Единые требования, постановление № 832',
    'СТ РК ISO/IEC 27001-2023', 'СТ РК ISO/IEC 27002-2023', 'СТ РК 1073-2007',
  ].join('\n');

  it('все шесть актов → PASS с указанием строки', async () => {
    const { get } = await evaluate({ 'README.md': `# P\n${ALL}\n` });
    expect(get('ИБ-06').status).toBe('PASS');
    expect(get('ИБ-06').evidence.every(e => e.line > 0 && e.filePath === 'README.md')).toBe(true);
  });

  it('пять из шести → нарушение с перечнем недостающего', async () => {
    const five = ALL.split('\n').filter(l => !l.includes('1073')).join('\n');
    const { get } = await evaluate({ 'README.md': five });
    const r = get('ИБ-06');
    expect(r.status).toBe('VIOLATION');
    expect(r.violations[0].explanation).toContain('1073');
    expect(r.violations[0].explanation).not.toContain('27001');
  });

  it('акты в разных документах засчитываются', async () => {
    const { get } = await evaluate({
      'README.md': ALL.split('\n').slice(0, 3).join('\n'),
      'docs/standards.md': ALL.split('\n').slice(3).join('\n'),
    });
    expect(get('ИБ-06').status).toBe('PASS');
  });

  it('документации нет вовсе → нарушение (отсутствие реализации, п. 4.4.5)', async () => {
    const { get } = await evaluate({ 'src/a.ts': 'export {}' });
    expect(get('ИБ-06').status).toBe('VIOLATION');
  });

  it('упоминание только в CHANGELOG/LICENSE не считается документацией проекта', async () => {
    const { get } = await evaluate({ 'README.md': '# p', 'CHANGELOG.md': ALL });
    expect(get('ИБ-06').status).toBe('VIOLATION');
  });
});

describe('ИБ-07: единый механизм против точечных логов', () => {
  it('access-лог без субъекта (user-agent — не субъект) не считается журналом действий', async () => {
    const { get } = await evaluate({
      'package.json': JSON.stringify({ dependencies: { '@nestjs/core': '^10' } }),
      'src/main.ts': 'app.useGlobalInterceptors(new LoggingInterceptor());',
      'src/logging.interceptor.ts':
        "export class LoggingInterceptor { intercept(ctx, next) { const ua = request.get('user-agent'); " +
        "this.logger.log(`${method} ${url} ${status} ${ip} ${ua}`); return next.handle(); } }",
      'src/orders.controller.ts': "@Controller('orders') class C { @Get('/orders') list() { return []; } @Post('/orders') add() {} }",
    });
    expect(get('ИБ-07').status).toBe('VIOLATION');
  });

  it('глобальный интерцептор с субъектом → единый механизм', async () => {
    const { get } = await evaluate({
      'package.json': JSON.stringify({ dependencies: { '@nestjs/core': '^10' } }),
      'src/main.ts': 'app.useGlobalInterceptors(new AuditInterceptor());',
      'src/audit.interceptor.ts':
        "export class AuditInterceptor { intercept(ctx, next) { const user = req.user; this.logger.log(`${user.id} ${method} ${url}`); return next.handle(); } }",
      'src/db.ts': "new PrismaClient({ log: ['query'] });",
      'src/orders.controller.ts': "@Controller('orders') class C { @Get('/orders') list() { return []; } }",
    });
    expect(get('ИБ-07').status).toBe('PASS');
  });

  it('logger.info в одном из нескольких обработчиков → нарушение (частичное покрытие)', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/a.routes.ts': "router.get('/a', (req, res) => { logger.info('user read a', { user: req.user }); res.json([]); });",
      'src/b.routes.ts': "router.get('/b', (req, res) => res.json([]));",
      'src/c.routes.ts': "router.get('/c', (req, res) => res.json([]));",
      'src/d.routes.ts': "router.get('/d', (req, res) => res.json([]));",
    });
    const r = get('ИБ-07');
    expect(r.status).toBe('VIOLATION');
    expect(r.violations.some(v => /из \d+ файлов/.test(v.evidence))).toBe(true);
  });

  it('отсутствие logger в файле не нарушение, если действует глобальный аудит', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/main.ts': 'app.use(auditMiddleware);',
      'src/audit.middleware.ts': "export const auditMiddleware = (req, res, next) => { auditLog.record({ actor: req.user.id, action: req.method }); next(); };",
      'src/audit.service.ts': 'export class AuditService { record(e) {} }',
      'src/b.routes.ts': "router.get('/b', (req, res) => res.json([]));",
      'src/db.ts': "new PrismaClient({ log: ['query'] });",
    });
    expect(get('ИБ-07').status).toBe('PASS');
  });
});

describe('ИБ-08: каждый поток выгрузки', () => {
  it('выгрузка только с ролью, без аудита → нарушение с указанием, чего не хватает', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/export.ts':
        "exportRouter.get('/export/users.csv', requireAdmin, async (req, res) => { res.download('/tmp/u.csv'); });",
    });
    const r = get('ИБ-08');
    expect(r.status).toBe('VIOLATION');
    expect(r.violations[0].explanation).toContain('журнал аудита');
    expect(r.violations[0].explanation).not.toContain('серверная проверка роли «администратор» и');
  });

  it('выгрузка без роли, но с аудитом → нарушение по роли', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'src/export.ts':
        "exportRouter.get('/export/users.csv', async (req, res) => { auditLog.record({ a: 1 }); res.download('/tmp/u.csv'); });",
    });
    expect(get('ИБ-08').violations[0].explanation).toContain('проверка роли');
  });

  it('CSV формируется только в браузере → серверной выгрузки нет', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/index.ts': "router.get('/orders', (req, res) => res.json([]));",
      'frontend/src/Export.tsx': "const blob = new Blob([rows.join(',')], { type: 'text/csv' });",
    });
    expect(get('ИБ-08').status).toBe('NOT_APPLICABLE');
  });

  it('выгрузка метрик — не персональные данные', async () => {
    const { get } = await evaluate({
      'package.json': EXPRESS,
      'server/metrics.ts': "router.get('/metrics/download', (req, res) => res.download('/tmp/metrics.csv'));",
    });
    expect(get('ИБ-08').status).not.toBe('VIOLATION');
  });
});

describe('Воспроизводимость и устойчивость', () => {
  it('сбой одной проверки не превращается в PASS и не роняет остальные', async () => {
    const { outcome } = await evaluate({ 'package.json': EXPRESS, 'src/a.ts': 'export {}' });
    expect(outcome.results).toHaveLength(8);
    for (const r of outcome.results) {
      if (r.status === 'INSUFFICIENT_EVIDENCE') expect(r.insufficientReason).toBeTruthy();
    }
  });

  it('файл с бинарным содержимым и огромной строкой не ломает индекс', async () => {
    const { outcome } = await evaluate({
      'package.json': EXPRESS,
      'src/bin.dat': String.fromCharCode(0, 1, 2, 3).repeat(1000),
      'src/long.ts': 'x'.repeat(500_000),
      'README.md': '# ok',
    });
    expect(outcome.results).toHaveLength(8);
  });
});
