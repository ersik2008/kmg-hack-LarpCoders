import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

export interface GroqResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

export interface GroqPoolStatus {
  provider: 'groq';
  configured: boolean;
  available: boolean;
  model: string;
  totalKeys: number;
  healthyKeys: number;
  coolingDownKeys: number;
  invalidKeys: number;
}

type KeyStatus = 'unknown' | 'healthy' | 'cooldown' | 'invalid';

interface ApiKeyState {
  key: string;
  status: KeyStatus;
  retryAt: number | null;
}

type KeyCallResult<T> = { ok: true; data: T } | { ok: false; error: string };

const TRANSIENT_NETWORK_CODES = new Set([
  'EAI_AGAIN', 'ENOTFOUND', 'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE',
]);

@Injectable()
export class GroqService {
  private readonly logger = new Logger(GroqService.name);
  private readonly model: string;
  private readonly baseUrl = 'https://api.groq.com/openai/v1/chat/completions';
  private readonly modelsUrl = 'https://api.groq.com/openai/v1/models';
  private readonly keyCooldownMs: number;
  private readonly keyProbeTimeoutMs: number;
  private readonly keys: ApiKeyState[];
  private nextKeyIndex = 0;
  private startupProbe: Promise<GroqPoolStatus> | null = null;

  constructor(private readonly configService: ConfigService) {
    this.keys = this.loadKeys(
      this.configService.get<string>('GROQ_API_KEYS'),
      this.configService.get<string>('GROQ_API_KEY'),
    );
    this.model = this.configService.get<string>('GROQ_MODEL') || 'openai/gpt-oss-120b';
    this.keyCooldownMs = this.positiveNumber('GROQ_KEY_COOLDOWN_MS', 15_000);
    this.keyProbeTimeoutMs = this.positiveNumber('GROQ_KEY_PROBE_TIMEOUT_MS', 5_000);
  }

  /**
   * Checks configured keys before serving traffic. Invalid/rate-limited keys
   * are skipped immediately until one usable key is found.
   */
  async warmUp(): Promise<GroqPoolStatus> {
    if (this.startupProbe) return this.startupProbe;

    this.startupProbe = (async () => {
      if (this.keys.length === 0) {
        this.logger.warn('No Groq API keys are configured. Set GROQ_API_KEYS or GROQ_API_KEY.');
        return this.getPoolStatus();
      }

      for (const state of this.keys) {
        await this.probeKey(state);
        if (state.status === 'healthy') break;
      }

      const status = this.getPoolStatus();
      if (status.available) {
        this.logger.log(
          'Groq key pool ready: ' + status.healthyKeys + '/' + status.totalKeys + ' key(s) healthy.',
        );
      } else {
        this.logger.warn(
          'No Groq key is ready (' + status.invalidKeys + ' invalid, ' +
          status.coolingDownKeys + ' cooling down).',
        );
      }
      return status;
    })();

    return this.startupProbe;
  }

  /** True when at least one configured key was not permanently rejected. */
  isConfigured(): boolean {
    return this.keys.some(state => state.status !== 'invalid');
  }

  /** Public readiness data deliberately excludes all API key material. */
  getPoolStatus(): GroqPoolStatus {
    this.refreshCooldowns();
    const count = (status: KeyStatus) => this.keys.filter(key => key.status === status).length;
    const healthyKeys = count('healthy');
    return {
      provider: 'groq',
      configured: this.keys.length > 0,
      available: healthyKeys > 0,
      model: this.model,
      totalKeys: this.keys.length,
      healthyKeys,
      coolingDownKeys: count('cooldown'),
      invalidKeys: count('invalid'),
    };
  }

  async invokeToolCalling(systemPrompt: string, messages: any[], tools: any[]) {
    const result = await this.requestChat<any>({
      model: this.model,
      messages: [{ role: 'system', content: systemPrompt }, ...messages],
      ...(tools && tools.length > 0 ? { tools, tool_choice: 'auto' } : {}),
      temperature: 0.1,
    }, 45_000);

    if (!result.ok) {
      this.logger.warn('Groq tool call unavailable: ' + result.error);
      return null;
    }
    return result.data?.choices?.[0]?.message || null;
  }

  /** Single-shot structured call with automatic key failover. */
  async completeJson<T = any>(systemPrompt: string, userPrompt: string): Promise<GroqResult<T>> {
    const result = await this.requestChat<any>({
      model: this.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      response_format: { type: 'json_object' },
      temperature: 0.1,
    }, 60_000);

    if (!result.ok) return result;
    const content = result.data?.choices?.[0]?.message?.content;
    if (!content) return { ok: false, error: 'модель вернула пустой ответ' };

    try {
      return { ok: true, data: JSON.parse(content) as T };
    } catch {
      this.logger.warn('Groq returned unparsable JSON.');
      return { ok: false, error: 'модель вернула невалидный JSON' };
    }
  }

  async analyze(prompt: string): Promise<string> {
    const result = await this.requestChat<any>({
      model: this.model,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
    }, 45_000);

    if (!result.ok) throw new Error('Groq analysis failed: ' + result.error);
    const content = result.data?.choices?.[0]?.message?.content;
    if (!content) throw new Error('Groq analysis failed: модель вернула пустой ответ');
    return content;
  }

  async explainFinding(finding: any, codeContext?: string): Promise<{
    title: string;
    reason: string;
    consequence: string;
    relatedFiles: string[];
    recommendedFix: string;
    beforeCode: string;
    afterCode: string;
    aiGenerated: boolean;
    unavailableReason: string | null;
  }> {
    const redact = (text: string) => {
      if (!text) return '';
      return text
        .replace(/(AKIA[0-9A-Z]{16})/g, 'AKIA****REDACTED****')
        .replace(/(ghp_[0-9a-zA-Z]{36})/g, 'ghp_****REDACTED****')
        .replace(/(postgres|mysql|mongodb(?:\+srv)?):\/\/[^@]+@/g, '$1://****:****@')
        .replace(/(?:password|passwd|pwd)\s*[:=]\s*['"\x60]([^'"\x60]+)['"\x60]/gi, 'password="****REDACTED****"');
    };

    const cleanSnippet = redact(codeContext || finding.codeSnippet || '');
    const cleanDesc = redact(finding.description || '');
    const systemPrompt = [
      'You are a Senior Security Architect and Code Auditor.',
      'Analyze this security finding and return ONLY valid JSON with title, reason, consequence,',
      'relatedFiles, recommendedFix, beforeCode, and afterCode fields.',
      'Use Russian for the explanation fields.',
    ].join('\n');
    const userPrompt = [
      'Уязвимость: ' + finding.title,
      'Сканер: ' + finding.scanner,
      'Файл: ' + finding.filePath + ':' + (finding.startLine || 1),
      'Описание: ' + cleanDesc,
      'Код:',
      cleanSnippet,
    ].join('\n');

    const response = await this.completeJson<{
      title?: string;
      reason?: string;
      consequence?: string;
      relatedFiles?: string[];
      recommendedFix?: string;
      beforeCode?: string;
      afterCode?: string;
    }>(systemPrompt, userPrompt);

    if (response.ok && response.data) {
      const parsed = response.data;
      return {
        title: parsed.title || finding.title,
        reason: parsed.reason || cleanDesc,
        consequence: parsed.consequence || '',
        relatedFiles: Array.isArray(parsed.relatedFiles) ? parsed.relatedFiles : [finding.filePath].filter(Boolean),
        recommendedFix: parsed.recommendedFix || '',
        beforeCode: parsed.beforeCode || cleanSnippet,
        afterCode: parsed.afterCode || '',
        aiGenerated: true,
        unavailableReason: null,
      };
    }

    return {
      title: finding.title,
      reason: cleanDesc,
      consequence: '',
      relatedFiles: [finding.filePath].filter(Boolean),
      recommendedFix: '',
      beforeCode: cleanSnippet,
      afterCode: '',
      aiGenerated: false,
      unavailableReason: 'Groq недоступен (' + (response.error || 'нет доступных ключей') +
        ') — показаны только данные сканера.',
    };
  }

  private async requestChat<T>(body: Record<string, unknown>, timeout: number): Promise<GroqResult<T>> {
    const result = await this.withKeyFailover(async key => {
      const response = await axios.post<T>(this.baseUrl, body, {
        headers: this.headers(key),
        timeout,
      });
      return response.data;
    });
    return result.ok ? { ok: true, data: result.data } : { ok: false, error: result.error };
  }

  /** Attempts each currently usable key once, never logging the key itself. */
  private async withKeyFailover<T>(request: (key: string) => Promise<T>): Promise<KeyCallResult<T>> {
    if (this.keys.length === 0) {
      return { ok: false, error: 'GROQ_API_KEYS/GROQ_API_KEY не настроены' };
    }

    const attempted = new Set<ApiKeyState>();
    let lastError: unknown;
    while (attempted.size < this.keys.length) {
      const state = this.selectNextKey(attempted);
      if (!state) break;
      attempted.add(state);

      try {
        const data = await request(state.key);
        this.markHealthy(state);
        return { ok: true, data };
      } catch (error) {
        lastError = error;
        this.markFailed(state, error);
      }
    }

    return { ok: false, error: this.safeFailureMessage(lastError) };
  }

  private async probeKey(state: ApiKeyState): Promise<void> {
    try {
      await axios.get(this.modelsUrl, {
        headers: this.headers(state.key),
        timeout: this.keyProbeTimeoutMs,
      });
      this.markHealthy(state);
    } catch (error) {
      this.markFailed(state, error);
    }
  }

  private selectNextKey(excluded: Set<ApiKeyState>): ApiKeyState | null {
    this.refreshCooldowns();
    return this.selectByStatus('healthy', excluded) || this.selectByStatus('unknown', excluded);
  }

  private selectByStatus(status: KeyStatus, excluded: Set<ApiKeyState>): ApiKeyState | null {
    for (let offset = 0; offset < this.keys.length; offset++) {
      const index = (this.nextKeyIndex + offset) % this.keys.length;
      const state = this.keys[index];
      if (state.status === status && !excluded.has(state)) {
        this.nextKeyIndex = (index + 1) % this.keys.length;
        return state;
      }
    }
    return null;
  }

  private markHealthy(state: ApiKeyState): void {
    state.status = 'healthy';
    state.retryAt = null;
  }

  private markFailed(state: ApiKeyState, error: unknown): void {
    const failure = this.classifyFailure(error);
    const label = 'key #' + (this.keys.indexOf(state) + 1);

    if (failure.kind === 'invalid') {
      state.status = 'invalid';
      state.retryAt = null;
      this.logger.warn('Groq ' + label + ' was rejected and disabled; trying the next configured key.');
      return;
    }

    state.status = 'cooldown';
    state.retryAt = Date.now() + failure.waitMs;
    this.logger.warn('Groq ' + label + ' is temporarily unavailable; trying the next configured key.');
  }

  private classifyFailure(error: unknown): { kind: 'invalid' | 'temporary'; waitMs: number } {
    const err = error as any;
    const status = Number(err?.response?.status);
    const code = String(err?.response?.data?.error?.code || '').toLowerCase();
    const message = String(err?.response?.data?.error?.message || err?.message || '').toLowerCase();
    const invalid = status === 401 || status === 403 ||
      code.includes('invalid_api_key') || /invalid (api )?key|authentication failed|unauthorized/.test(message);
    if (invalid) return { kind: 'invalid', waitMs: 0 };

    const rateLimited = status === 429 || code === 'rate_limit_exceeded';
    const transient = TRANSIENT_NETWORK_CODES.has(err?.code) || err?.code === 'ECONNABORTED';
    return {
      kind: 'temporary',
      waitMs: rateLimited ? this.rateLimitWaitMs(err) : (transient ? this.keyCooldownMs : this.keyCooldownMs),
    };
  }

  private rateLimitWaitMs(err: any): number {
    const header = Number(err?.response?.headers?.['retry-after']);
    if (Number.isFinite(header) && header > 0) return Math.min(header * 1000, 300_000);

    const message = String(err?.response?.data?.error?.message || '');
    const match = message.match(/try again in ([0-9.]+)s/i);
    if (match) return Math.min(Math.ceil(Number(match[1])) * 1000 + 1_000, 300_000);
    return this.keyCooldownMs;
  }

  private safeFailureMessage(lastError: unknown): string {
    this.refreshCooldowns();
    if (this.keys.every(state => state.status === 'invalid')) {
      return 'все настроенные Groq API-ключи отклонены провайдером';
    }
    if (this.keys.some(state => state.status === 'cooldown')) {
      return 'все доступные Groq API-ключи временно недоступны';
    }
    const status = (lastError as any)?.response?.status;
    return status ? 'Groq API ответил HTTP ' + status : 'Groq API недоступен';
  }

  private refreshCooldowns(): void {
    const now = Date.now();
    for (const state of this.keys) {
      if (state.status === 'cooldown' && state.retryAt != null && state.retryAt <= now) {
        state.status = 'unknown';
        state.retryAt = null;
      }
    }
  }

  private headers(key: string): Record<string, string> {
    return { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' };
  }

  private loadKeys(poolValue?: string, legacyValue?: string): ApiKeyState[] {
    const values = [poolValue, legacyValue]
      .flatMap(value => this.parseKeyList(value))
      .filter((key, index, list) => list.indexOf(key) === index);
    return values.map(key => ({ key, status: 'unknown', retryAt: null }));
  }

  private parseKeyList(value?: string): string[] {
    if (!value) return [];
    const trimmed = value.trim();
    if (!trimmed || trimmed === 'your-groq-api-key') return [];

    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return parsed.filter((key): key is string => typeof key === 'string').map(key => key.trim());
        }
      } catch {
        // Fall back to the documented comma/newline list format.
      }
    }

    return trimmed.split(/[\r\n,;]+/).map(key => key.trim()).filter(Boolean);
  }

  private positiveNumber(key: string, fallback: number): number {
    const value = Number(this.configService.get<string>(key));
    return Number.isFinite(value) && value > 0 ? value : fallback;
  }
}
