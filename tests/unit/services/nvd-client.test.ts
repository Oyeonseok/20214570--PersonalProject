import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getCveDetail, cvssToSeverity, clearNvdCache } from '../../../src/services/nvd-client.js';

beforeEach(() => {
  clearNvdCache();
  vi.restoreAllMocks();
  delete process.env.NVD_API_KEY;
});

describe('NVD Client', () => {
  it('getCveDetail parses NVD response correctly', async () => {
    const mockBody = {
      vulnerabilities: [{
        cve: {
          id: 'CVE-2021-23337',
          descriptions: [{ lang: 'en', value: 'Test vulnerability description' }],
          metrics: {
            cvssMetricV31: [{
              cvssData: { baseScore: 7.2, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' },
            }],
          },
          weaknesses: [{ description: [{ lang: 'en', value: 'CWE-77' }] }],
          references: [{ url: 'https://example.com', source: 'test' }],
          published: '2021-02-15',
          lastModified: '2024-01-01',
        },
      }],
    };

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockBody),
    }));

    const result = await getCveDetail('CVE-2021-23337');
    expect(result).not.toBeNull();
    expect(result!.cveId).toBe('CVE-2021-23337');
    expect(result!.cvss?.baseScore).toBe(7.2);
    expect(result!.cvss?.baseSeverity).toBe('HIGH');
    expect(result!.cweIds).toContain('CWE-77');
    expect(result!.description).toBe('Test vulnerability description');
  });

  it('getCveDetail returns null for 404', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404, statusText: 'Not Found' }));
    const result = await getCveDetail('CVE-0000-0000');
    expect(result).toBeNull();
  });

  it('getCveDetail returns null for empty vulnerabilities', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ vulnerabilities: [] }),
    }));
    const result = await getCveDetail('CVE-0000-0001');
    expect(result).toBeNull();
  });

  it('getCveDetail uses cache on second call', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        vulnerabilities: [{
          cve: {
            id: 'CVE-2024-0001',
            descriptions: [{ lang: 'en', value: 'cached' }],
            metrics: {},
            weaknesses: [],
            references: [],
          },
        }],
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await getCveDetail('CVE-2024-0001');
    await getCveDetail('CVE-2024-0001');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('getCveDetail sends API key header when available', async () => {
    process.env.NVD_API_KEY = 'test-key-123';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ vulnerabilities: [] }),
    }));

    await getCveDetail('CVE-2024-0002');
    const fetchCall = (fetch as any).mock.calls[0];
    expect(fetchCall[1].headers.apiKey).toBe('test-key-123');
  });

  it('cvssToSeverity maps scores correctly', () => {
    expect(cvssToSeverity(9.8)).toBe('critical');
    expect(cvssToSeverity(9.0)).toBe('critical');
    expect(cvssToSeverity(7.5)).toBe('high');
    expect(cvssToSeverity(7.0)).toBe('high');
    expect(cvssToSeverity(5.0)).toBe('medium');
    expect(cvssToSeverity(4.0)).toBe('medium');
    expect(cvssToSeverity(2.0)).toBe('low');
    expect(cvssToSeverity(0)).toBe('info');
  });
});
