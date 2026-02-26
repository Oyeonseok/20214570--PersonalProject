import { describe, it, expect } from 'vitest';
import { handleScanCode } from '../../../src/tools/scan-code.js';

describe('handleScanCode', () => {
  it('returns markdown report for vulnerable code', () => {
    const result = handleScanCode({
      code: 'element.innerHTML = userInput;\neval(code);',
      language: 'javascript',
      severity_threshold: 'low',
    });
    expect(result.content[0].text).toContain('보안 스캔 결과');
    expect(result.structuredResult).toBeDefined();
    expect(result.structuredResult!.vulnerabilities.length).toBeGreaterThan(0);
  });

  it('returns clean report for safe code', () => {
    const result = handleScanCode({
      code: 'const x = 1;',
      language: 'javascript',
      severity_threshold: 'low',
    });
    expect(result.content[0].text).toContain('취약점 없음');
  });

  it('includes suggestions in result', () => {
    const result = handleScanCode({
      code: 'element.innerHTML = data;',
      language: 'javascript',
      severity_threshold: 'low',
    });
    expect(result.structuredResult!.suggestions).toBeDefined();
  });
});
