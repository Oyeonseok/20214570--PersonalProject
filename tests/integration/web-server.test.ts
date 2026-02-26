import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';

vi.stubEnv('ANTHROPIC_API_KEY', 'test-key-for-testing');
vi.stubEnv('PORT', '0');

describe('Express Web Server', () => {
  let app: any;
  let server: any;
  let baseUrl: string;

  beforeAll(async () => {
    const mod = await import('../../src/app/server.js');
    app = mod.app ?? mod.default;

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      if (server) server.close(() => resolve());
      else resolve();
    });
  });

  it('GET /api/status returns 200', async () => {
    const res = await fetch(`${baseUrl}/api/status`);
    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
  });

  it('POST /api/chat with empty message returns 400', async () => {
    const res = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: '' }),
    });
    expect(res.status).toBe(400);
  });

  it('serves static files', async () => {
    const res = await fetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('html');
  });

  it('includes security headers in response', async () => {
    const res = await fetch(`${baseUrl}/api/status`);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
  });
});
