import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import * as http from 'http';
import * as https from 'https';

export interface OllamaResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

export interface OllamaPoolStatus {
  provider: 'ollama';
  configured: boolean;
  available: boolean;
  model: string;
  baseUrl: string;
}

@Injectable()
export class OllamaService implements OnModuleInit {
  private readonly logger = new Logger(OllamaService.name);
  private readonly model: string;
  private readonly baseUrl: string;
  /** Ollama OpenAI-compatible chat endpoint */
  private readonly chatUrl: string;
  /** Ollama tags endpoint for health check */
  private readonly tagsUrl: string;
  private available = false;
  /** Retry timer handle */
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryCount = 0;
  private readonly MAX_RETRIES = 20;
  private readonly RETRY_INTERVAL_MS = 30_000;

  constructor(private readonly configService: ConfigService) {
    this.baseUrl =
      this.configService.get<string>('OLLAMA_BASE_URL') ||
      'http://100.78.81.65:11434';
    this.model =
      this.configService.get<string>('OLLAMA_MODEL') || 'qwen3:latest';
    // Ollama exposes an OpenAI-compatible endpoint at /v1/chat/completions
    this.chatUrl = `${this.baseUrl}/v1/chat/completions`;
    this.tagsUrl = `${this.baseUrl}/api/tags`;
  }

  async onModuleInit(): Promise<void> {
    await this.warmUp();
  }

  /**
   * Проверяет доступность Ollama при старте. Никогда не бросает исключение —
   * недоступный Ollama не должен останавливать запуск приложения.
   */
  async warmUp(): Promise<OllamaPoolStatus> {
    try {
      const resp = await axios.get<{ models: { name: string }[] }>(
        this.tagsUrl,
        { timeout: 5_000 },
      );
      const models: string[] = (resp.data?.models ?? []).map(
        (m: { name: string }) => m.name,
      );
      // Считаем готовым, если нужная модель уже загружена
      this.available = models.some(
        (m) => m === this.model || m.startsWith(this.model.split(':')[0]),
      );
      if (this.available) {
        this.logger.log(
          `Ollama ready at ${this.baseUrl}. Model: ${this.model}. Available models: ${models.join(', ')}`,
        );
      } else {
        this.logger.warn(
          `Ollama is reachable but model "${this.model}" was not found. ` +
            `Available: ${models.join(', ') || '(none)'}. ` +
            `Requests will still be attempted.`,
        );
        // Разрешаем попытку даже если модель не найдена в /api/tags —
        // Ollama автоматически скачает её при первом вызове.
        this.available = true;
      }
    } catch (err) {
      const msg = (err as any)?.message ?? String(err);
      this.logger.warn(
        `Ollama is not reachable at ${this.baseUrl}: ${msg}. AI features will be degraded.`,
      );
      this.available = false;
      this.scheduleRetry();
    }

    return this.getStatus();
  }

  /** Schedule a retry warmUp if we are not available yet. */
  private scheduleRetry(): void {
    if (this.retryTimer !== null || this.retryCount >= this.MAX_RETRIES) return;
    this.retryCount++;
    this.logger.log(
      `Ollama retry #${this.retryCount} scheduled in ${this.RETRY_INTERVAL_MS / 1000}s`,
    );
    this.retryTimer = setTimeout(async () => {
      this.retryTimer = null;
      const status = await this.warmUp();
      if (!status.available) {
        this.scheduleRetry();
      } else {
        this.retryCount = 0;
        this.logger.log('Ollama reconnected successfully.');
      }
    }, this.RETRY_INTERVAL_MS);
  }

  isConfigured(): boolean {
    return !!this.baseUrl;
  }

  /** Force an immediate re-check and reset retry counter. */
  async forceRetry(): Promise<OllamaPoolStatus> {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    this.retryCount = 0;
    return this.warmUp();
  }

  getStatus(): OllamaPoolStatus {
    return {
      provider: 'ollama',
      configured: this.isConfigured(),
      available: this.available,
      model: this.model,
      baseUrl: this.baseUrl,
    };
  }

  // ─── Public API (mirrors GroqService) ───────────────────────────────────────

  /**
   * Вызов с инструментами (tool calling). Ollama поддерживает tool calling
   * через тот же OpenAI-совместимый формат.
   */
  async invokeToolCalling(
    systemPrompt: string,
    messages: any[],
    tools: any[],
  ): Promise<any | null> {
    const result = await this.requestChat<any>(
      {
        model: this.model,
        messages: [{ role: 'system', content: systemPrompt }, ...messages],
        ...(tools && tools.length > 0 ? { tools, tool_choice: 'auto' } : {}),
        temperature: 0.1,
        stream: false,
      },
      180_000,
    );

    if (!result.ok) {
      this.logger.warn('Ollama tool call unavailable: ' + result.error);
      return null;
    }
    return result.data?.choices?.[0]?.message || null;
  }

  /**
   * Структурированный JSON-ответ. Ollama поддерживает format: json_object.
   */
  async completeJson<T = any>(
    systemPrompt: string,
    userPrompt: string,
  ): Promise<OllamaResult<T>> {
    const result = await this.requestChat<any>(
      {
        model: this.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.1,
        stream: false,
      },
      300_000,
    );

    if (!result.ok) return result;
    let content: string = result.data?.choices?.[0]?.message?.content ?? '';

    // Убираем блоки <think>...</think>, которые модель иногда вставляет
    // в content даже при think:false (переходный период прошивки Ollama)
    content = content.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();

    if (!content) return { ok: false, error: 'модель вернула пустой ответ' };

    // Извлекаем от первой { до последней }
    const firstBrace = content.indexOf('{');
    const lastBrace = content.lastIndexOf('}');
    
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      const jsonStr = content.substring(firstBrace, lastBrace + 1);
      try {
        return { ok: true, data: JSON.parse(jsonStr) as T };
      } catch (err) {
        // Если все еще ошибка (например, неэкранированные символы)
        this.logger.warn('Ollama JSON parse error after extraction: ' + err);
        /* fall through */
      }
    }
    
    this.logger.warn(
      'Ollama returned unparsable JSON: ' + content.slice(0, 200),
    );
    return { ok: false, error: 'модель вернула невалидный JSON' };
  }

  async analyze(prompt: string): Promise<string> {
    const result = await this.requestChat<any>(
      {
        model: this.model,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        stream: false,
      },
      300_000,
    );

    if (!result.ok) throw new Error('Ollama analysis failed: ' + result.error);
    let content: string = result.data?.choices?.[0]?.message?.content ?? '';
    // Убираем блоки <think>...</think>
    content = content.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
    if (!content)
      throw new Error('Ollama analysis failed: модель вернула пустой ответ');
    return content;
  }

  async explainFinding(
    finding: any,
    codeContext?: string,
  ): Promise<{
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
        .replace(
          /(postgres|mysql|mongodb(?:\+srv)?):\/\/[^@]+@/g,
          '$1://****:****@',
        )
        .replace(
          /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
          'password="****REDACTED****"',
        );
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
        relatedFiles: Array.isArray(parsed.relatedFiles)
          ? parsed.relatedFiles
          : [finding.filePath].filter(Boolean),
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
      unavailableReason:
        'Ollama недоступен (' +
        (response.error || 'нет ответа') +
        ') — показаны только данные сканера.',
    };
  }

  // ─── Internal ────────────────────────────────────────────────────────────────

  /**
   * HTTP-агент с keep-alive, чтобы не открывать новый TCP-сокет на каждый
   * запрос. Это снижает вероятность ECONNRESET при долгих генерациях.
   */
  private readonly httpAgent = new http.Agent({ keepAlive: true, maxSockets: 4 });
  private readonly httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 4 });

  private async requestChat<T>(
    body: Record<string, unknown>,
    timeout: number,
  ): Promise<OllamaResult<T>> {
    if (!this.available) {
      return {
        ok: false,
        error: `Ollama недоступен по адресу ${this.baseUrl}`,
      };
    }

    return this.doRequest<T>(body, timeout, /* isRetry */ false);
  }

  private async doRequest<T>(
    body: Record<string, unknown>,
    timeout: number,
    isRetry: boolean,
  ): Promise<OllamaResult<T>> {
    try {
      const response = await axios.post<T>(this.chatUrl, body, {
        headers: { 'Content-Type': 'application/json' },
        timeout,
        httpAgent: this.httpAgent,
        httpsAgent: this.httpsAgent,
      });
      return { ok: true, data: response.data };
    } catch (error) {
      const msg = this.errorMessage(error);
      this.logger.warn(`Ollama request failed${isRetry ? ' (retry)' : ''}: ${msg}`);

      if (this.isTransientError(error)) {
        // ECONNRESET и подобные — соединение сбросилось, но Ollama жива.
        // Повторяем один раз с небольшой паузой.
        if (!isRetry) {
          this.logger.log('Ollama transient error, retrying once in 2s...');
          await new Promise(r => setTimeout(r, 2_000));
          return this.doRequest<T>(body, timeout, /* isRetry */ true);
        }
        // После второй неудачи — не помечаем как недоступный, просто возвращаем ошибку.
        return { ok: false, error: msg };
      }

      if (this.isFatalNetworkError(error)) {
        // ECONNREFUSED / EAI_AGAIN — сервер реально недостижим.
        this.available = false;
        this.scheduleRetry();
      }

      return { ok: false, error: msg };
    }
  }

  /**
   * Transient-ошибки: соединение сбросилось в процессе, но сервер жив.
   * Retry имеет смысл.
   */
  private isTransientError(error: unknown): boolean {
    const code = (error as any)?.code;
    return ['ECONNRESET', 'EPIPE', 'ENOTFOUND'].includes(code);
  }

  /**
   * Fatal-ошибки: сервер недостижим вообще. Помечаем как unavailable.
   */
  private isFatalNetworkError(error: unknown): boolean {
    const code = (error as any)?.code;
    return ['ECONNREFUSED', 'EAI_AGAIN', 'ETIMEDOUT'].includes(code);
  }

  private errorMessage(error: unknown): string {
    const err = error as any;
    const status = err?.response?.status;
    const detail =
      err?.response?.data?.error?.message ||
      err?.response?.data?.error ||
      err?.message;
    if (status) return `HTTP ${status}: ${detail || ''}`;
    return String(detail || error);
  }
}
