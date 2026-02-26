import { describe, it, expect } from 'vitest';
import { handleSecureCode, generateDiff } from '../../../src/tools/secure-code.js';

describe('handleSecureCode', () => {
  it('returns vulnerability report for insecure code', () => {
    const result = handleSecureCode({
      code: 'element.innerHTML = userInput;',
      language: 'javascript',
    });
    expect(result.content[0].text).toContain('취약점');
    expect(result.content[0].text).not.toContain('✅ 취약점 없음');
  });

  it('returns safe message for secure code', () => {
    const result = handleSecureCode({
      code: 'const x = 1;\nconsole.log(x);',
      language: 'javascript',
    });
    expect(result.content[0].text).toContain('✅');
  });

  it('reports security headers for HTML', () => {
    const result = handleSecureCode({
      code: '<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>',
    });
    expect(result.content[0].text).toContain('보안헤더');
  });

  it('auto-detects language when not specified', () => {
    const result = handleSecureCode({
      code: 'def main():\n    print("hello")',
    });
    expect(result.content).toBeDefined();
  });

  describe('show_comparison mode', () => {
    it('shows Before/After comparison for insecure JS code', () => {
      const result = handleSecureCode({
        code: 'element.innerHTML = userInput;',
        language: 'javascript',
        show_comparison: true,
      });
      const text = result.content[0].text;
      expect(text).toContain('보안 분석 요약');
      expect(text).toContain('Before (취약)');
      expect(text).toContain('After (시큐어)');
      expect(text).toContain('최종 시큐어코딩 적용 코드');
      expect(text).toContain('textContent');
    });

    it('shows severity summary table in comparison', () => {
      const result = handleSecureCode({
        code: 'element.innerHTML = userInput;',
        language: 'javascript',
        show_comparison: true,
      });
      const text = result.content[0].text;
      expect(text).toContain('심각도');
      expect(text).toContain('건수');
    });

    it('shows auto-fix detail table in comparison', () => {
      const result = handleSecureCode({
        code: 'element.innerHTML = userInput;',
        language: 'javascript',
        show_comparison: true,
      });
      const text = result.content[0].text;
      expect(text).toContain('자동 수정 내역');
      expect(text).toContain('규칙');
    });

    it('shows security headers in HTML comparison', () => {
      const code = '<!DOCTYPE html><html><head><title>T</title></head><body><a href="x" target="_blank">link</a></body></html>';
      const result = handleSecureCode({ code, show_comparison: true });
      const text = result.content[0].text;
      expect(text).toContain('추가된 보안 헤더');
    });

    it('includes full secured code block in comparison', () => {
      const result = handleSecureCode({
        code: 'element.innerHTML = userInput;\nconsole.log("ok");',
        language: 'javascript',
        show_comparison: true,
      });
      const text = result.content[0].text;
      expect(text).toContain('최종 시큐어코딩 적용 코드');
      expect(text).toContain('textContent');
    });

    it('still returns safe message when no vulnerabilities with show_comparison', () => {
      const result = handleSecureCode({
        code: 'const x = 1;\nconsole.log(x);',
        language: 'javascript',
        show_comparison: true,
      });
      expect(result.content[0].text).toContain('✅');
    });

    it('defaults show_comparison to false', () => {
      const result = handleSecureCode({
        code: 'element.innerHTML = userInput;',
        language: 'javascript',
      });
      const text = result.content[0].text;
      expect(text).not.toContain('Before (취약)');
      expect(text).toContain('코드 수정');
    });
  });
});

describe('generateDiff', () => {
  it('detects unchanged lines', () => {
    const diff = generateDiff('a\nb\nc', 'a\nb\nc');
    expect(diff.every((d) => d.type === 'unchanged')).toBe(true);
  });

  it('detects modified lines', () => {
    const diff = generateDiff('x.innerHTML = v;', 'x.textContent = v;');
    expect(diff.some((d) => d.type === 'modified')).toBe(true);
    const mod = diff.find((d) => d.type === 'modified')!;
    expect(mod.original).toBe('x.innerHTML = v;');
    expect(mod.secured).toBe('x.textContent = v;');
  });

  it('detects added lines', () => {
    const diff = generateDiff('line1\nline2', 'line1\nnewline\nline2');
    const added = diff.filter((d) => d.type === 'added' || d.type === 'modified');
    expect(added.length).toBeGreaterThan(0);
  });

  it('handles empty input gracefully', () => {
    const diff = generateDiff('', '');
    expect(diff.length).toBe(1);
    expect(diff[0].type).toBe('unchanged');
  });

  it('handles original longer than secured', () => {
    const diff = generateDiff('a\nb\nc', 'a');
    const removed = diff.filter((d) => d.type === 'removed' || d.type === 'modified');
    expect(removed.length).toBeGreaterThan(0);
  });
});
