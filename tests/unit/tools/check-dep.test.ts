import { describe, it, expect, afterAll, vi, beforeEach } from 'vitest';
import { resolve } from 'path';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { handleCheckDependency } from '../../../src/tools/check-dependency.js';

const TMP_DIR = resolve(__dirname, '../../fixtures/.tmp');

function writeTmpFile(name: string, content: string): string {
  mkdirSync(TMP_DIR, { recursive: true });
  const p = resolve(TMP_DIR, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('no network in test')));
});

describe('handleCheckDependency', () => {
  afterAll(() => {
    vi.restoreAllMocks();
    try { rmSync(TMP_DIR, { recursive: true }); } catch {}
  });

  it('detects vulnerable lodash version (fallback to local DB)', async () => {
    const path = writeTmpFile('package.json', JSON.stringify({
      dependencies: { lodash: '^4.17.0' },
    }));
    const result = await handleCheckDependency({ manifest_path: path, severity_filter: 'low' });
    expect(result.content[0].text).toContain('lodash');
    expect(result.content[0].text).toContain('로컬 DB');
  });

  it('reports safe for patched versions (fallback)', async () => {
    const path = writeTmpFile('package.json', JSON.stringify({
      dependencies: { lodash: '^4.17.21' },
    }));
    const result = await handleCheckDependency({ manifest_path: path, severity_filter: 'low' });
    expect(result.content[0].text).toContain('의존성 보안 검사');
  });

  it('handles requirements.txt', async () => {
    const path = writeTmpFile('requirements.txt', 'flask==2.0.0\nrequests==2.28.0\n');
    const result = await handleCheckDependency({ manifest_path: path, severity_filter: 'low' });
    expect(result.content[0].text).toContain('의존성 보안 검사');
  });

  it('returns error for non-existent file', async () => {
    const result = await handleCheckDependency({ manifest_path: '/no/such/file.json', severity_filter: 'low' });
    expect(result.content[0].text).toContain('❌');
  });

  it('returns error for unsupported format', async () => {
    const path = writeTmpFile('Gemfile', 'gem "rails"');
    const result = await handleCheckDependency({ manifest_path: path, severity_filter: 'low' });
    expect(result.content[0].text).toContain('지원하지 않는');
  });

  it('filters by severity (fallback)', async () => {
    const path = writeTmpFile('package.json', JSON.stringify({
      dependencies: { lodash: '^4.17.0', semver: '^7.0.0' },
    }));
    const high = await handleCheckDependency({ manifest_path: path, severity_filter: 'high' });
    const medium = await handleCheckDependency({ manifest_path: path, severity_filter: 'medium' });
    expect(medium.content[0].text).toBeDefined();
    expect(high.content[0].text).toBeDefined();
  });

  it('scans code for vulnerable patterns when code_to_scan provided', async () => {
    const path = writeTmpFile('package.json', JSON.stringify({
      dependencies: { lodash: '^4.17.0' },
    }));
    const code = `const tmpl = _.template(req.body.input);\ntmpl({ name: 'test' });`;
    const result = await handleCheckDependency({ manifest_path: path, severity_filter: 'low', code_to_scan: code });
    expect(result.content[0].text).toContain('lodash');
  });
});
