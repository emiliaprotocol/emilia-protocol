/**
 * Tests for lib/providers/embeddings.js
 * Covers: generateEmbedding — happy paths, no-provider path, error handling
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

vi.mock('@/lib/env', () => ({
  getOpenAIKey: vi.fn(),
}));

import { getOpenAIKey } from '@/lib/env';
import { generateEmbedding } from '@/lib/providers/embeddings.js';

const FAKE_VECTOR = Array.from({ length: 1536 }, (_, i) => i / 1536);

function mockOkResponse(embedding = FAKE_VECTOR) {
  return {
    ok: true,
    status: 200,
    json: vi.fn().mockResolvedValue({ data: [{ embedding }] }),
  };
}

function mockErrorResponse(status = 500) {
  return { ok: false, status, json: vi.fn() };
}

describe('generateEmbedding', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('returns null immediately when text is empty string', async () => {
    getOpenAIKey.mockReturnValue('sk-test');
    const result = await generateEmbedding('');
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('returns null immediately when text is null', async () => {
    getOpenAIKey.mockReturnValue('sk-test');
    const result = await generateEmbedding(null);
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('returns null immediately when text is undefined', async () => {
    getOpenAIKey.mockReturnValue('sk-test');
    const result = await generateEmbedding(undefined);
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('returns null when no OpenAI key is configured', async () => {
    getOpenAIKey.mockReturnValue(null);
    const result = await generateEmbedding('hello world');
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('calls OpenAI embeddings API with correct URL and method', async () => {
    getOpenAIKey.mockReturnValue('sk-abc123');
    fetch.mockResolvedValue(mockOkResponse());
    await generateEmbedding('test text');
    expect(fetch).toHaveBeenCalledWith(
      'https://api.openai.com/v1/embeddings',
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('sends Authorization header with bearer token', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse());
    await generateEmbedding('test text');
    const [, opts] = fetch.mock.calls[0];
    expect(opts.headers.Authorization).toBe('Bearer sk-mykey');
  });

  it('sends Content-Type application/json', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse());
    await generateEmbedding('test text');
    const [, opts] = fetch.mock.calls[0];
    expect(opts.headers['Content-Type']).toBe('application/json');
  });

  it('uses text-embedding-3-small model in request body', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse());
    await generateEmbedding('hello');
    const [, opts] = fetch.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.model).toBe('text-embedding-3-small');
  });

  it('sends the input text in request body', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse());
    await generateEmbedding('my test input');
    const [, opts] = fetch.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.input).toBe('my test input');
  });

  it('returns the embedding vector on successful API response', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse(FAKE_VECTOR));
    const result = await generateEmbedding('test text');
    expect(result).toEqual(FAKE_VECTOR);
  });

  it('returned vector is an array of numbers', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse(FAKE_VECTOR));
    const result = await generateEmbedding('test text');
    expect(Array.isArray(result)).toBe(true);
    expect(typeof result[0]).toBe('number');
  });

  it('returns null when API responds with non-OK status', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockErrorResponse(429));
    const result = await generateEmbedding('rate limited text');
    expect(result).toBeNull();
  });

  it('returns null when fetch throws a network error', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockRejectedValue(new Error('Network error'));
    const result = await generateEmbedding('some text');
    expect(result).toBeNull();
  });

  it('returns null (not throw) when API throws during json parsing', async () => {
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockRejectedValue(new Error('Bad JSON')),
    });
    const result = await generateEmbedding('some text');
    expect(result).toBeNull();
  });

  it('handles custom-length embedding vectors correctly', async () => {
    const customVector = [0.1, 0.2, 0.3, 0.4];
    getOpenAIKey.mockReturnValue('sk-mykey');
    fetch.mockResolvedValue(mockOkResponse(customVector));
    const result = await generateEmbedding('short');
    expect(result).toEqual(customVector);
    expect(result.length).toBe(4);
  });
});
