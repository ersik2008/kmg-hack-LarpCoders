import { describe, it, expect } from 'vitest';
import { gzipSync } from 'zlib';

import { inspectTarGz } from '../src/ci/tar-inspector.js';
import { toFindingRow } from '../src/scan/finding-row.util.js';
import { dedupeFindings, categoryOf } from '../src/scan/finding-dedup.util.js';
import { SecretRedactor } from '../src/common/utils/secret-redactor.js';
import { SarifService } from '../src/scan/sarif.service.js';
import { PrepushService } from '../src/prepush/prepush.service.js';
import { ArchitectureService } from '../src/scan/architecture.service.js';

/** Минимальный tar: 512-байтные заголовки + данные, выровненные по блоку. */
function tarHeader(name: string, size: number, typeFlag = '0', linkName = ''): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(typeFlag, 156);
  if (linkName) h.write(linkName, 157, 100, 'utf8');
  h.write('ustar\0', 257);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

function tarEntry(name: string, content = '', typeFlag = '0', linkName = ''): Buffer {
  const data = Buffer.from(content);
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([tarHeader(name, data.length, typeFlag, linkName), padded]);
}

const tarGz = (...entries: Buffer[]) =>
  gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));

describe('inspectTarGz — архив недоверенный', () => {
  it('обычный архив принимается', () => {
    const r = inspectTarGz(tarGz(tarEntry('src/app.ts', 'export {}'), tarEntry('README.md', '# x')));
    expect(r.rejection).toBeNull();
    expect(r.entries).toBe(2);
  });

  it('выход через .. отклоняется до распаковки', () => {
    const r = inspectTarGz(tarGz(tarEntry('../../etc/passwd', 'x')));
    expect(r.rejection).toMatch(/небезопасный путь/);
  });

  it('вложенный .. в середине пути отклоняется', () => {
    expect(inspectTarGz(tarGz(tarEntry('a/../../b', 'x'))).rejection).toMatch(/небезопасный путь/);
  });

  it('абсолютный путь отклоняется', () => {
    expect(inspectTarGz(tarGz(tarEntry('/etc/cron.d/x', 'x'))).rejection).toMatch(/небезопасный путь/);
  });

  it('windows-путь отклоняется', () => {
    expect(inspectTarGz(tarGz(tarEntry('C:/Windows/x', 'x'))).rejection).toMatch(/небезопасный путь/);
  });

  it('символическая ссылка за пределы архива отклоняется', () => {
    const r = inspectTarGz(tarGz(tarEntry('link', '', '2', '../../etc/shadow')));
    expect(r.rejection).toMatch(/ссылка за пределы/);
  });

  it('жёсткая ссылка за пределы архива отклоняется', () => {
    const r = inspectTarGz(tarGz(tarEntry('hard', '', '1', '/etc/passwd')));
    expect(r.rejection).toMatch(/ссылка за пределы/);
  });

  it('символическая ссылка внутри архива допустима', () => {
    expect(inspectTarGz(tarGz(tarEntry('a', 'x'), tarEntry('b', '', '2', 'a'))).rejection).toBeNull();
  });

  it('архивная бомба по объёму отклоняется', () => {
    const r = inspectTarGz(tarGz(tarEntry('big.bin', 'x'.repeat(4096))), { maxTotalBytes: 1024 });
    expect(r.rejection).toMatch(/превышает/);
  });

  it('архивная бомба по числу записей отклоняется', () => {
    const many = Array.from({ length: 6 }, (_, i) => tarEntry(`f${i}`, 'x'));
    expect(inspectTarGz(tarGz(...many), { maxEntries: 3 }).rejection).toMatch(/больше 3 записей/);
  });

  it('не gzip отклоняется', () => {
    expect(inspectTarGz(Buffer.from('not a gzip')).rejection).toMatch(/gzip/);
  });

  it('пустой архив отклоняется', () => {
    expect(inspectTarGz(gzipSync(Buffer.alloc(1024))).rejection).toMatch(/пуст/);
  });

  it('длинное имя с выходом за пределы (GNU L) отклоняется', () => {
    const longName = '../'.repeat(2) + 'x'.repeat(120);
    const r = inspectTarGz(tarGz(tarEntry('././@LongLink', longName + '\0', 'L'), tarEntry('short', 'x')));
    expect(r.rejection).toMatch(/небезопасный путь/);
  });
});

describe('PrepushService.safeRelativePath — пути из запроса', () => {
  const svc = Object.create(PrepushService.prototype) as any;
  const safe = (p: string) => svc.safeRelativePath(p);

  it('обычные пути принимаются и нормализуются', () => {
    expect(safe('src/app.ts')).toBe('src/app.ts');
    expect(safe('./src/app.ts')).toBe('src/app.ts');
    expect(safe('src\\app.ts')).toBe('src/app.ts');
  });

  it('выход за пределы рабочей области отклоняется', () => {
    expect(safe('../secret')).toBeNull();
    expect(safe('a/../../b')).toBeNull();
    expect(safe('..\\..\\windows')).toBeNull();
  });

  it('абсолютные и дисковые пути отклоняются', () => {
    expect(safe('/etc/passwd')).toBeNull();
    expect(safe('C:\\Windows\\system32')).toBeNull();
  });

  it('пустые пути отклоняются', () => {
    expect(safe('')).toBeNull();
    expect(safe('.')).toBeNull();
  });
});

describe('ArchitectureService.readFileContent — traversal при чтении', () => {
  const arch = new ArchitectureService();
  it('отклоняет выход из рабочей области', async () => {
    await expect(arch.readFileContent(process.cwd(), '../../../etc/passwd')).rejects.toThrow();
  });
});

describe('toFindingRow — внешние данные', () => {
  it('некорректная severity не роняет запись', () => {
    expect(toFindingRow('s', { scanner: 'x', severity: 'ULTRA', title: 't' }).severity).toBe('MEDIUM');
  });

  it('пустой заголовок заменяется идентификатором правила', () => {
    expect(toFindingRow('s', { scanner: 'x', severity: 'LOW', ruleId: 'rule-1' }).title).toBe('rule-1');
  });

  it('длинные строки обрезаются по колонкам БД', () => {
    const row = toFindingRow('s', { scanner: 'x', severity: 'LOW', title: 'a'.repeat(9000), filePath: 'p'.repeat(5000) });
    expect(row.title.length).toBe(500);
    expect((row.filePath ?? '').length).toBe(1000);
  });

  it('некорректный номер строки становится null', () => {
    expect(toFindingRow('s', { scanner: 'x', severity: 'LOW', title: 't', startLine: -3 }).startLine).toBeNull();
    expect(toFindingRow('s', { scanner: 'x', severity: 'LOW', title: 't', startLine: 'abc' }).startLine).toBeNull();
  });

  it('detectedBy сохраняется в metadata', () => {
    const row = toFindingRow('s', { scanner: 'semgrep', severity: 'HIGH', title: 't', detectedBy: ['semgrep', 'trivy'] });
    expect((row.metadata as any).detectedBy).toEqual(['semgrep', 'trivy']);
  });
});

describe('SecretRedactor', () => {
  it('маскирует токены, ключи, URI БД и JWT', () => {
    // Значения собираются на лету: литерал в исходнике сам стал бы находкой
    // Gitleaks при проверке этого репозитория.
    const src = [
      'ghp_' + 'a'.repeat(36),
      'gsk_' + 'b'.repeat(52),
      'AKIA' + 'ABCDEFGHIJKLMNOP',
      ['postgresql', '://user:', 'pa55w0rd', '@db:5432/app'].join(''),
      ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxIn0', 'abc123'].join('.'),
    ].join(' ');
    const out = SecretRedactor.redact(src);
    expect(out).not.toContain('a'.repeat(36));
    expect(out).not.toContain('b'.repeat(52));
    expect(out).not.toContain('ABCDEFGHIJKLMNOP');
    expect(out).not.toContain('pa55w0rd');
    expect(out).not.toContain('eyJzdWIiOiIxIn0');
  });

  it('redactObject скрывает значения чувствительных полей по имени', () => {
    const out = SecretRedactor.redactObject({ user: 'u', password: 'p', nested: { apiKey: 'k', ok: 1 } });
    expect(out.password).toBe('***REDACTED***');
    expect(out.nested.apiKey).toBe('***REDACTED***');
    expect(out.nested.ok).toBe(1);
  });
});

describe('Дедупликация находок между сканерами', () => {
  const f = (over: any) => ({ scanner: 'semgrep', severity: 'HIGH', confidence: 'HIGH', title: 't', filePath: 'a.ts', startLine: 10, ...over });

  it('один секрет от Gitleaks, Trivy и Semgrep — одна находка с тремя источниками', () => {
    const out = dedupeFindings([
      f({ scanner: 'gitleaks', ruleId: 'aws-access-token', title: 'Exposed secret: aws-access-token', severity: 'CRITICAL', codeSnippet: '***REDACTED***' }),
      f({ scanner: 'trivy', ruleId: 'aws-access-key-id', title: 'Exposed secret: AWS Access Key ID', severity: 'CRITICAL', codeSnippet: '***REDACTED***' }),
      f({ scanner: 'semgrep', ruleId: 'generic.secrets.hardcoded-api-key', title: 'Hardcoded API key', severity: 'HIGH', codeSnippet: 'const k = "AKIA..."' }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].detectedBy).toEqual(['gitleaks', 'trivy', 'semgrep']);
    expect(out[0].severity).toBe('CRITICAL');
    expect(out[0].category).toBe('secret');
    // Секрет остаётся замаскированным, даже если один из инструментов его раскрыл.
    expect(out[0].codeSnippet).toBe('***REDACTED***');
  });

  it('берётся наибольшая критичность', () => {
    const out = dedupeFindings([
      f({ scanner: 'semgrep', ruleId: 'sqli-1', title: 'SQL injection', severity: 'MEDIUM' }),
      f({ scanner: 'builtin_fallback', ruleId: 'fallback-sql-injection-risk', title: '[Fallback] Potential SQL Injection', severity: 'CRITICAL' }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe('CRITICAL');
  });

  it('разные строки одного файла — разные находки', () => {
    const out = dedupeFindings([
      f({ ruleId: 'sqli', title: 'SQL injection', startLine: 10 }),
      f({ ruleId: 'sqli', title: 'SQL injection', startLine: 20 }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('разные категории на одной строке не сливаются', () => {
    const out = dedupeFindings([
      f({ ruleId: 'sqli', title: 'SQL injection' }),
      f({ ruleId: 'xss', title: 'Reflected XSS' }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('одна CVE в разных lock-файлах — разные находки (разные места)', () => {
    const out = dedupeFindings([
      f({ scanner: 'trivy', ruleId: 'CVE-2021-23337', title: 'lodash@4.17.15: CVE-2021-23337', filePath: 'package-lock.json' }),
      f({ scanner: 'trivy', ruleId: 'CVE-2021-23337', title: 'lodash@4.17.15: CVE-2021-23337', filePath: 'frontend/package-lock.json' }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('одна CVE, продублированная в одном файле, объединяется', () => {
    const out = dedupeFindings([
      f({ scanner: 'trivy', ruleId: 'CVE-2021-23337', title: 'x', filePath: 'package-lock.json', startLine: null }),
      f({ scanner: 'trivy', ruleId: 'CVE-2021-23337', title: 'x', filePath: 'package-lock.json', startLine: null }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].category).toBe('dependency');
  });

  it('неопознанная категория сливается только при полном совпадении', () => {
    const out = dedupeFindings([
      f({ ruleId: 'custom-1', title: 'Something odd', scanner: 'semgrep' }),
      f({ ruleId: 'custom-2', title: 'Something odd', scanner: 'semgrep' }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('путь нормализуется: ./a.ts и a.ts — одно место', () => {
    const out = dedupeFindings([
      f({ scanner: 'semgrep', ruleId: 'x', title: 'SQL injection', filePath: './a.ts' }),
      f({ scanner: 'trivy', ruleId: 'y', title: 'SQL injection', filePath: 'a.ts' }),
    ]);
    expect(out).toHaveLength(1);
  });

  it('порядок первого появления сохраняется', () => {
    const out = dedupeFindings([
      f({ ruleId: 'a', title: 'XSS', startLine: 1 }),
      f({ ruleId: 'b', title: 'SQL injection', startLine: 2 }),
      f({ ruleId: 'c', title: 'XSS', startLine: 1, scanner: 'trivy' }),
    ]);
    expect(out.map(x => x.startLine)).toEqual([1, 2]);
  });

  it('пустой ввод и один элемент', () => {
    expect(dedupeFindings([])).toEqual([]);
    expect(dedupeFindings([f({ ruleId: 'r', title: 'XSS' })])).toHaveLength(1);
  });

  it('categoryOf: CVE у Trivy — зависимость; прочее — по словам', () => {
    expect(categoryOf({ scanner: 'trivy', ruleId: 'CVE-2020-1', title: 'pkg' })).toBe('dependency');
    expect(categoryOf({ scanner: 'semgrep', ruleId: 'x', title: 'Server-Side Request Forgery' })).toBe('ssrf');
    expect(categoryOf({ scanner: 'semgrep', ruleId: 'x', title: 'zzz' })).toBe('other');
  });
});

describe('SarifService — отчёт', () => {
  const scan: any = {
    id: 'scan-1',
    commitSha: 'abc123',
    branch: 'main',
    policyResult: 'BLOCK',
    riskScore: 10,
    repository: { fullName: 'o/r', url: 'https://github.com/o/r', defaultBranch: 'main' },
    findings: [
      { scanner: 'semgrep', ruleId: 'r one', severity: 'CRITICAL', confidence: 'HIGH', title: 'SQLi', description: 'd', filePath: './src/a.ts', startLine: 4, endLine: 5, codeSnippet: 'q' },
      { scanner: 'gitleaks', ruleId: 'aws', severity: 'CRITICAL', confidence: 'HIGH', title: 'Secret', description: null, filePath: 'c.ts', startLine: null, endLine: null, codeSnippet: '***REDACTED***' },
    ],
    controls: [
      { control: 'AUDIT_LOGGING', title: 'Аудит', status: 'MISSING', summary: 's', risk: 'r', recommendation: 'x', evidence: [{ filePath: 'src/l.ts', line: 3 }] },
      { control: 'CRYPTOGRAPHY', title: 'Крипто', status: 'MISSING', summary: 's', risk: 'r', recommendation: 'x', evidence: [] },
      { control: 'SESSIONS', title: 'Сессии', status: 'IMPLEMENTED', summary: 's', risk: null, recommendation: null, evidence: [] },
    ],
    scanResult: null,
  };
  const svc = new SarifService({ scan: { findFirst: async () => scan } } as any);

  it('версия и схема SARIF 2.1.0', async () => {
    const s = await svc.build('u', 'scan-1');
    expect(s.version).toBe('2.1.0');
    expect(s.$schema).toContain('sarif-2.1.0');
  });

  it('пути относительные, строка не меньше 1', async () => {
    const [a, b] = (await svc.build('u', 'scan-1')).runs[0].results;
    expect(a.locations[0].physicalLocation.artifactLocation.uri).toBe('src/a.ts');
    expect(b.locations[0].physicalLocation.region.startLine).toBe(1);
  });

  it('severity → level и security-severity', async () => {
    const run = (await svc.build('u', 'scan-1')).runs[0];
    expect(run.results[0].level).toBe('error');
    expect(run.tool.driver.rules[0].properties['security-severity']).toBe('9.5');
  });

  it('контроль без доказательства не экспортируется, а с доказательством — да', async () => {
    const run = (await svc.build('u', 'scan-1')).runs[0];
    const controls = run.results.filter((r: any) => String(r.ruleId).startsWith('kmg-control/'));
    expect(controls).toHaveLength(1);
    expect(controls[0].ruleId).toBe('kmg-control/audit_logging');
  });

  it('стабильный отпечаток для отслеживания находки между прогонами', async () => {
    const a = (await svc.build('u', 'scan-1')).runs[0].results[0].partialFingerprints.primaryLocationLineHash;
    const b = (await svc.build('u', 'scan-1')).runs[0].results[0].partialFingerprints.primaryLocationLineHash;
    expect(a).toBe(b);
    expect(a).toHaveLength(32);
  });

  it('commit SHA и ветка попадают в provenance', async () => {
    const prov = (await svc.build('u', 'scan-1')).runs[0].versionControlProvenance[0];
    expect(prov.revisionId).toBe('abc123');
    expect(prov.branch).toBe('main');
  });

  it('несуществующий скан → NotFound', async () => {
    const missing = new SarifService({ scan: { findFirst: async () => null } } as any);
    await expect(missing.build('u', 'x')).rejects.toThrow();
  });
});

import { RepositoryService } from '../src/repository/repository.service.js';

describe('RepositoryService: значения, попадающие в аргументы git', () => {
  it('допустимые имена репозиториев', () => {
    for (const ok of ['owner/name', 'Org-1/repo.name', 'a_b/c-d.e']) {
      expect(RepositoryService.isValidFullName(ok), ok).toBe(true);
    }
  });

  it('метасимволы оболочки и опции git в имени репозитория отклоняются', () => {
    for (const bad of [
      'owner/name; rm -rf /', 'owner/name && curl x', 'owner/$(id)', 'owner/`id`', 'owner/name|cat',
      '--upload-pack=evil/x', 'owner', 'owner/', '/name', 'a/b/c', '../etc/passwd', 'owner/na me', 'owner/name\nx',
    ]) {
      expect(RepositoryService.isValidFullName(bad), bad).toBe(false);
    }
  });

  it('допустимые имена веток', () => {
    for (const ok of ['main', 'feature/login', 'release-1.2', 'fix_123']) {
      expect(RepositoryService.isValidBranch(ok), ok).toBe(true);
    }
  });

  it('ветка, похожая на опцию git или содержащая метасимволы, отклоняется', () => {
    for (const bad of [
      '-upload-pack=x', '--help', 'main; id', 'a b', 'a$(id)', 'x`id`', '../x', 'a..b', '', 'x\ny', 'a|b', 'a&b',
    ]) {
      expect(RepositoryService.isValidBranch(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  it('токен не попадает в текст ошибки', () => {
    const svc = Object.create(RepositoryService.prototype) as any;
    const token = 'gho_supersecrettoken123456';
    const b64 = Buffer.from(`x-access-token:${token}`).toString('base64');
    const out = svc.scrub(`fatal: could not read ${token} and AUTHORIZATION: basic ${b64}`, token);
    expect(out).not.toContain(token);
    expect(out).not.toContain(b64);
  });
});
