import { describe, it, expect, vi, beforeEach } from 'vitest';
import { queryBatch, getVulnDetail, extractCveId, extractGhsaId, extractFixedVersion, clearOsvCache } from '../../../src/services/osv-client.js';

beforeEach(() => {
  clearOsvCache();
  vi.restoreAllMocks();
});

describe('OSV Client', () => {
  it('queryBatch returns empty for empty input', async () => {
    const result = await queryBatch([]);
    expect(result.results).toEqual([]);
  });

  it('queryBatch calls OSV API with correct format', async () => {
    const mockResponse = { results: [{ vulns: [{ id: 'GHSA-test', modified: '2024-01-01' }] }] };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    }));

    const result = await queryBatch([{ name: 'lodash', ecosystem: 'npm', version: '4.17.0' }]);
    expect(result.results[0].vulns).toHaveLength(1);
    expect(result.results[0].vulns![0].id).toBe('GHSA-test');

    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[0]).toBe('https://api.osv.dev/v1/querybatch');
    expect(fetchCall[1].method).toBe('POST');
  });

  it('queryBatch uses cache on second call', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ results: [{ vulns: [] }] }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await queryBatch([{ name: 'express', ecosystem: 'npm', version: '4.0.0' }]);
    await queryBatch([{ name: 'express', ecosystem: 'npm', version: '4.0.0' }]);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('queryBatch throws on API error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500, statusText: 'Server Error' }));
    await expect(queryBatch([{ name: 'test', ecosystem: 'npm' }])).rejects.toThrow('OSV API error');
  });

  it('getVulnDetail fetches vulnerability details', async () => {
    const mockVuln = { id: 'GHSA-test', summary: 'Test vuln', aliases: ['CVE-2024-0001'] };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockVuln),
    }));

    const detail = await getVulnDetail('GHSA-test');
    expect(detail.id).toBe('GHSA-test');
    expect(detail.summary).toBe('Test vuln');
  });

  it('extractCveId finds CVE from aliases', () => {
    expect(extractCveId({ id: 'GHSA-abc', aliases: ['CVE-2024-1234'] } as any)).toBe('CVE-2024-1234');
    expect(extractCveId({ id: 'CVE-2024-1234' } as any)).toBe('CVE-2024-1234');
    expect(extractCveId({ id: 'GHSA-abc', aliases: [] } as any)).toBeUndefined();
  });

  it('extractGhsaId finds GHSA from ID or aliases', () => {
    expect(extractGhsaId({ id: 'GHSA-abc-def', aliases: [] } as any)).toBe('GHSA-abc-def');
    expect(extractGhsaId({ id: 'CVE-2024-1234', aliases: ['GHSA-xyz'] } as any)).toBe('GHSA-xyz');
  });

  it('extractFixedVersion finds fixed version from events', () => {
    const vuln = {
      id: 'test',
      affected: [{
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      }],
    } as any;
    expect(extractFixedVersion(vuln, 'lodash')).toBe('4.17.21');
    expect(extractFixedVersion(vuln, 'unknown')).toBeUndefined();
  });
});
