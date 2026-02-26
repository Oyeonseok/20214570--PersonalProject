import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleSearchCve } from '../../../src/tools/search-cve.js';

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('handleSearchCve', () => {
  it('searches by package name using local patterns', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('no network')));

    const result = await handleSearchCve({ query: 'lodash' });
    expect(result.content[0].text).toContain('lodash');
    expect(result.content[0].text).toContain('CVE-2021-23337');
  });

  it('searches by package name and scans code', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('no network')));

    const result = await handleSearchCve({
      query: 'lodash',
      code_snippet: `const out = _.template(req.body.tmpl);\nout({});`,
    });
    expect(result.content[0].text).toContain('위험 패턴 발견');
  });

  it('reports no patterns for safe code', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('no network')));

    const result = await handleSearchCve({
      query: 'lodash',
      code_snippet: `const x = _.map([1,2,3], n => n * 2);`,
    });
    expect(result.content[0].text).toContain('위험 패턴이 발견되지 않았습니다');
  });

  it('searches by CVE ID with OSV fallback', async () => {
    const mockVuln = {
      id: 'GHSA-35jh-r3h4-6jhm',
      summary: 'lodash template injection',
      aliases: ['CVE-2021-23337'],
      affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
      references: [{ type: 'ADVISORY', url: 'https://example.com' }],
    };

    let callCount = 0;
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      callCount++;
      if (url.includes('osv.dev')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockVuln) });
      }
      return Promise.resolve({ ok: false, status: 404, statusText: 'Not Found' });
    }));

    const result = await handleSearchCve({ query: 'CVE-2021-23337' });
    expect(result.content[0].text).toContain('CVE-2021-23337');
    expect(result.content[0].text).toContain('취약점 상세');
  });

  it('returns fallback message for unknown package', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('no network')));

    const result = await handleSearchCve({ query: 'totally-unknown-pkg' });
    expect(result.content[0].text).toContain('알려진 취약점이 없습니다');
  });
});
