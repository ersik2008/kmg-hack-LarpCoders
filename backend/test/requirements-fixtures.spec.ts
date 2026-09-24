import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import { RequirementsService } from '../src/requirements/requirements.service.js';
import type { RequirementResult } from '../src/requirements/requirement-definitions.js';

/**
 * Регрессия обнаружения по фикстурам security-test-repository/requirements.
 *
 * До появления этого набора каталог фикстур не был подключён ни к одному
 * прогону: изменение правил не замечалось никаким тестом, а доля пропусков и
 * ложных срабатываний не измерялась вовсе.
 *
 *   violating — нарушено каждое из ИБ-01…ИБ-08 (контроль пропусков);
 *   compliant — тот же состав, реализованный корректно (контроль ложных
 *               срабатываний, ТЗ п. 5.3).
 */

const ROOT = path.resolve(__dirname, '../../security-test-repository/requirements');
const expected = JSON.parse(fs.readFileSync(path.join(ROOT, 'expected.json'), 'utf8'));

// Оценка требований не обращается к БД, поэтому заглушки достаточно.
const service = new RequirementsService({} as any);

async function evaluate(name: 'violating' | 'compliant') {
  const outcome = await service.evaluate(path.join(ROOT, name), `fixture:${name}`);
  const byId = new Map<string, RequirementResult>(outcome.results.map(r => [r.requirementId, r]));
  return { outcome, byId };
}

const IDS = ['ИБ-01', 'ИБ-02', 'ИБ-03', 'ИБ-04', 'ИБ-05', 'ИБ-06', 'ИБ-07', 'ИБ-08'];

describe('Требования ИБ-01…ИБ-08 на фикстурах', () => {
  describe('violating: нет пропусков', () => {
    for (const id of IDS) {
      it(`${id} выявляется как VIOLATION`, async () => {
        const { byId } = await evaluate('violating');
        const result = byId.get(id)!;
        expect(result, `${id} отсутствует в результате`).toBeDefined();
        expect(result.status, result.summary).toBe(expected.violating[id].status);
      });
    }

    it('каждое нарушение содержит место, доказательство, обоснование, критичность и рекомендацию (ТЗ п. 4.6.2)', async () => {
      const { outcome } = await evaluate('violating');
      for (const r of outcome.violations) {
        expect(r.violations.length, `${r.requirementId}: нет описания нарушения`).toBeGreaterThan(0);
        for (const v of r.violations) {
          expect(v.evidence, `${r.requirementId}: пустое доказательство`).toBeTruthy();
          expect(v.explanation.length, `${r.requirementId}: общее обоснование`).toBeGreaterThan(40);
          expect(v.recommendation, `${r.requirementId}: нет рекомендации`).toBeTruthy();
          expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(v.severity);
        }
        // Формулировка без указания места не признаётся описанием нарушения (п. 4.6.4).
        // Допустимое исключение — нарушение через отсутствие механизма в проекте целиком.
        const located = r.violations.filter(v => v.filePath);
        expect(located.length, `${r.requirementId}: ни одного нарушения с местом`).toBeGreaterThan(0);
      }
    });

    for (const id of IDS) {
      const exp = expected.violating[id];
      if (!exp.file) continue;
      it(`${id}: нарушение указывает на ${exp.file}`, async () => {
        const { byId } = await evaluate('violating');
        const files = byId.get(id)!.violations.map(v => v.filePath);
        expect(files).toContain(exp.file);
      });
    }

    it('ИБ-04: SHA-256 для пароля — нарушение с указанием строки', async () => {
      const { byId } = await evaluate('violating');
      const v = byId.get('ИБ-04')!.violations.find(x => x.filePath === 'src/auth/password.ts')!;
      expect(v).toBeDefined();
      expect(v.lineStart).toBe(expected.violating['ИБ-04'].line);
      expect(v.evidence).toMatch(/sha256/i);
    });

    it('ИБ-08: указано, чего именно не хватает потоку выгрузки', async () => {
      const { byId } = await evaluate('violating');
      const text = byId.get('ИБ-08')!.violations.map(v => v.explanation).join(' ');
      expect(text).toMatch(/проверка роли/);
      expect(text).toMatch(/журнал аудита/);
    });

    it('ИБ-06: перечислены все шесть ненайденных актов', async () => {
      const { byId } = await evaluate('violating');
      const text = byId.get('ИБ-06')!.violations[0].explanation;
      for (const act of ['418-V', '94-V', '832', '27001', '27002', '1073']) {
        expect(text, `в объяснении нет акта ${act}`).toContain(act);
      }
    });
  });

  describe('compliant: нет ложных срабатываний', () => {
    for (const id of IDS) {
      it(`${id} — PASS`, async () => {
        const { byId } = await evaluate('compliant');
        const result = byId.get(id)!;
        expect(result.status, `${id}: ${result.summary} ${JSON.stringify(result.violations.map(v => v.explanation))}`)
          .toBe(expected.compliant[id].status);
      });
    }

    it('нарушений нет вообще', async () => {
      const { outcome } = await evaluate('compliant');
      expect(outcome.violations.map(v => v.requirementId)).toEqual([]);
    });
  });

  describe('свойства статусов', () => {
    it('в результате всегда ровно восемь требований, по одному на идентификатор', async () => {
      for (const name of ['violating', 'compliant'] as const) {
        const { outcome } = await evaluate(name);
        expect(outcome.results.map(r => r.requirementId)).toEqual(IDS);
      }
    });

    it('статус допустимый; INSUFFICIENT_EVIDENCE объясняет причину', async () => {
      for (const name of ['violating', 'compliant'] as const) {
        const { outcome } = await evaluate(name);
        for (const r of outcome.results) {
          expect(['PASS', 'VIOLATION', 'INSUFFICIENT_EVIDENCE', 'NOT_APPLICABLE']).toContain(r.status);
          if (r.status === 'INSUFFICIENT_EVIDENCE') expect(r.insufficientReason).toBeTruthy();
          if (r.status === 'VIOLATION') expect(r.violations.length).toBeGreaterThan(0);
          if (r.status === 'PASS') expect(r.violations.length).toBe(0);
        }
      }
    });

    it('результат воспроизводим: два прогона дают одинаковые статусы', async () => {
      const a = await evaluate('violating');
      const b = await evaluate('violating');
      expect(a.outcome.results.map(r => [r.requirementId, r.status]))
        .toEqual(b.outcome.results.map(r => [r.requirementId, r.status]));
    });
  });
});
