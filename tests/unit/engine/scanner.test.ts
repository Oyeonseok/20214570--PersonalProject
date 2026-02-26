import { describe, it, expect } from 'vitest';
import { scanCode } from '../../../src/engine/scanner.js';

describe('scanCode', () => {
  describe('XSS detection', () => {
    it('detects innerHTML assignment', () => {
      const code = 'element.innerHTML = userInput;';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-79')).toBe(true);
    });

    it('detects innerHTML +=', () => {
      const code = 'el.innerHTML += data;';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-79')).toBe(true);
    });

    it('detects document.write', () => {
      const code = 'document.write(userInput);';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-79')).toBe(true);
    });

    it('does not flag innerHTML with empty string', () => {
      const code = "element.innerHTML = '';";
      const result = scanCode(code, { language: 'javascript' });
      const xssVulns = result.vulnerabilities.filter(
        (v) => v.cweId === 'CWE-79' && v.matchedCode.includes('innerHTML'),
      );
      expect(xssVulns.length).toBe(0);
    });
  });

  describe('SQL Injection detection', () => {
    it('detects string concatenation in SQL', () => {
      const code = 'const q = `SELECT * FROM users WHERE id = ${userId}`;';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-89')).toBe(true);
    });
  });

  describe('hardcoded secrets detection', () => {
    it('detects hardcoded API keys', () => {
      const code = 'const API_KEY = "sk-secret-key-12345678901234567890";';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-798')).toBe(true);
    });
  });

  describe('eval detection', () => {
    it('detects eval usage', () => {
      const code = 'eval(userInput);';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-94')).toBe(true);
    });
  });

  describe('language filtering', () => {
    it('applies JavaScript rules to JavaScript code', () => {
      const code = 'element.innerHTML = data;';
      const result = scanCode(code, { language: 'javascript' });
      expect(result.language).toBe('javascript');
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
    });

    it('applies Python rules to Python code', () => {
      const code = 'os.system("ls " + user_input)';
      const result = scanCode(code, { language: 'python' });
      expect(result.language).toBe('python');
    });
  });

  describe('severity threshold', () => {
    it('filters by severity threshold', () => {
      const code = 'element.innerHTML = data;\neval(x);';
      const allResult = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
      const criticalOnly = scanCode(code, { language: 'javascript', severityThreshold: 'critical' });
      expect(allResult.vulnerabilities.length).toBeGreaterThanOrEqual(criticalOnly.vulnerabilities.length);
    });
  });

  describe('empty input', () => {
    it('returns zero vulnerabilities for empty code', () => {
      const result = scanCode('');
      expect(result.vulnerabilities.length).toBe(0);
      expect(result.summary.totalIssues).toBe(0);
    });
  });

  describe('result structure', () => {
    it('includes required fields', () => {
      const result = scanCode('const x = 1;', { language: 'javascript' });
      expect(result.scanId).toBeDefined();
      expect(result.timestamp).toBeDefined();
      expect(result.targetType).toBe('code');
      expect(result.language).toBe('javascript');
      expect(result.summary).toBeDefined();
      expect(result.vulnerabilities).toBeDefined();
      expect(result.suggestions).toBeDefined();
    });

    it('uses "file" targetType when filePath is provided', () => {
      const result = scanCode('const x = 1;', { filePath: 'test.js' });
      expect(result.targetType).toBe('file');
    });
  });

  describe('rule exclusion', () => {
    it('excludes specified rules', () => {
      const code = 'element.innerHTML = data;';
      const withRule = scanCode(code, { language: 'javascript' });
      const xssRuleId = withRule.vulnerabilities.find((v) => v.cweId === 'CWE-79')?.ruleId;
      if (xssRuleId) {
        const without = scanCode(code, { language: 'javascript', excludeRules: [xssRuleId] });
        expect(without.vulnerabilities.filter((v) => v.ruleId === xssRuleId).length).toBe(0);
      }
    });
  });
});
