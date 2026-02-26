import { describe, it, expect } from 'vitest';
import { CWE_DATABASE, getCweResource } from '../../../src/resources/cwe-database.js';
import { OWASP_TOP10_2021, getOwaspResource } from '../../../src/resources/owasp-top10.js';
import { SECURE_PATTERNS, getSecurePatternsResource } from '../../../src/resources/secure-patterns.js';

describe('CWE Database', () => {
  it('has entries', () => {
    expect(CWE_DATABASE.length).toBeGreaterThan(0);
  });

  it('every entry has required fields', () => {
    for (const entry of CWE_DATABASE) {
      expect(entry.id).toMatch(/^CWE-\d+$/);
      expect(entry.name).toBeTruthy();
      expect(entry.nameKo).toBeTruthy();
      expect(entry.url).toContain('cwe.mitre.org');
    }
  });

  it('getCweResource returns table for no arg', () => {
    const result = getCweResource();
    expect(result).toContain('CWE');
    expect(result).toContain('|');
  });

  it('getCweResource returns detail for specific CWE', () => {
    const result = getCweResource('CWE-89');
    expect(result).toContain('SQL');
  });

  it('getCweResource returns error for unknown CWE', () => {
    const result = getCweResource('CWE-99999');
    expect(result).toContain('찾을 수 없습니다');
  });
});

describe('OWASP Top 10', () => {
  it('has 10 entries', () => {
    expect(OWASP_TOP10_2021.length).toBe(10);
  });

  it('every entry has required fields', () => {
    for (const item of OWASP_TOP10_2021) {
      expect(item.id).toMatch(/^A\d{2}:2021$/);
      expect(item.name).toBeTruthy();
      expect(item.nameKo).toBeTruthy();
      expect(item.prevention.length).toBeGreaterThan(0);
      expect(item.preventionKo.length).toBeGreaterThan(0);
      expect(item.cwes.length).toBeGreaterThan(0);
    }
  });

  it('getOwaspResource returns formatted text', () => {
    const result = getOwaspResource('2021');
    expect(result).toContain('OWASP Top 10');
    expect(result).toContain('A01');
  });

  it('getOwaspResource returns error for unsupported year', () => {
    const result = getOwaspResource('2019');
    expect(result).toContain('2021만 지원');
  });
});

describe('Secure Patterns', () => {
  it('has patterns', () => {
    expect(SECURE_PATTERNS.length).toBeGreaterThan(0);
  });

  it('getSecurePatternsResource returns formatted text', () => {
    const result = getSecurePatternsResource();
    expect(result).toBeTruthy();
    expect(result.length).toBeGreaterThan(100);
  });
});
