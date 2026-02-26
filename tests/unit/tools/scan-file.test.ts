import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { handleScanFile } from '../../../src/tools/scan-file.js';

const FIXTURES = resolve(__dirname, '../../fixtures');

describe('handleScanFile', () => {
  it('scans vulnerable JS file and finds issues', () => {
    const result = handleScanFile({
      file_path: resolve(FIXTURES, 'vulnerable/xss-sample.js'),
      rule_sets: ['owasp'],
      exclude_rules: [],
      severity_threshold: 'low',
    });
    expect(result.content[0].text).toContain('보안 스캔');
    expect(result.structuredResult).toBeDefined();
    expect(result.structuredResult!.vulnerabilities.length).toBeGreaterThan(0);
  });

  it('scans safe JS file with minimal issues', () => {
    const result = handleScanFile({
      file_path: resolve(FIXTURES, 'secure/safe-sample.js'),
      rule_sets: ['owasp'],
      exclude_rules: [],
      severity_threshold: 'low',
    });
    expect(result.content[0].text).toContain('보안 스캔');
  });

  it('returns error for non-existent file', () => {
    const result = handleScanFile({
      file_path: '/nonexistent/file.js',
      rule_sets: ['owasp'],
      exclude_rules: [],
      severity_threshold: 'low',
    });
    expect(result.content[0].text).toContain('❌');
  });

  it('returns error for unsupported file type', () => {
    const result = handleScanFile({
      file_path: resolve(FIXTURES, 'configs/sample.env'),
      rule_sets: ['owasp'],
      exclude_rules: [],
      severity_threshold: 'low',
    });
    expect(result.content[0].text).toContain('지원하지 않는');
  });
});
