import { beforeEach, describe, expect, it, vi } from 'vitest';
import axios from 'axios';

import { GroqService } from '../src/ai/groq.service.js';

vi.mock('axios');

const mockedAxios = axios as any;
const jsonReply = (value: Record<string, unknown>) => ({
  data: { choices: [{ message: { content: JSON.stringify(value) } }] },
});

function createService(values: Record<string, string | undefined>) {
  return new GroqService({
    get: (key: string) => values[key],
  } as any);
}

describe('GroqService key pool', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('skips an invalid startup key and marks the next working key healthy', async () => {
    mockedAxios.get
      .mockRejectedValueOnce({ response: { status: 401, data: { error: { code: 'invalid_api_key' } } } })
      .mockResolvedValueOnce({ data: { data: [] } });
    const service = createService({ GROQ_API_KEYS: 'invalid-key,working-key' });

    const status = await service.warmUp();

    expect(status).toMatchObject({
      configured: true,
      available: true,
      totalKeys: 2,
      healthyKeys: 1,
      invalidKeys: 1,
    });
    expect(mockedAxios.get.mock.calls.map((call: any[]) => call[1].headers.Authorization)).toEqual([
      'Bearer invalid-key',
      'Bearer working-key',
    ]);
  });

  it('retries a structured request with the next key after an authentication failure', async () => {
    mockedAxios.post
      .mockRejectedValueOnce({ response: { status: 403, data: { error: { message: 'Unauthorized' } } } })
      .mockResolvedValueOnce(jsonReply({ verdict: 'BLOCK' }));
    const service = createService({ GROQ_API_KEYS: 'rejected-key,working-key' });

    await expect(service.completeJson<{ verdict: string }>('system', 'user')).resolves.toEqual({
      ok: true,
      data: { verdict: 'BLOCK' },
    });
    expect(mockedAxios.post.mock.calls.map((call: any[]) => call[2].headers.Authorization)).toEqual([
      'Bearer rejected-key',
      'Bearer working-key',
    ]);
    expect(service.getPoolStatus()).toMatchObject({ healthyKeys: 1, invalidKeys: 1 });
  });

  it('puts a rate-limited key on cooldown and keeps using the next healthy key', async () => {
    mockedAxios.post
      .mockRejectedValueOnce({ response: { status: 429, headers: { 'retry-after': '60' } } })
      .mockResolvedValueOnce(jsonReply({ report: 'first' }))
      .mockResolvedValueOnce(jsonReply({ report: 'second' }));
    const service = createService({ GROQ_API_KEYS: 'limited-key,working-key' });

    await expect(service.completeJson('system', 'first')).resolves.toMatchObject({ ok: true });
    await expect(service.completeJson('system', 'second')).resolves.toMatchObject({ ok: true });

    expect(mockedAxios.post.mock.calls.map((call: any[]) => call[2].headers.Authorization)).toEqual([
      'Bearer limited-key',
      'Bearer working-key',
      'Bearer working-key',
    ]);
    expect(service.getPoolStatus()).toMatchObject({ healthyKeys: 1, coolingDownKeys: 1 });
  });
});
