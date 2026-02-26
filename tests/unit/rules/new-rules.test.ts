import { describe, it, expect } from 'vitest';
import { scanCode } from '../../../src/engine/scanner.js';

describe('SCG-AUF-CSRF-002: Empty CSRF Token', () => {
  it('detects empty CSRF token value', () => {
    const code = '<input type="hidden" name="_csrf" id="csrfToken" value="">';
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const csrf002 = result.vulnerabilities.find((v) => v.ruleId === 'SCG-AUF-CSRF-002');
    expect(csrf002).toBeDefined();
    expect(csrf002!.severity).toBe('high');
  });

  it('detects empty CSRF token with reversed attributes', () => {
    const code = '<input value="" name="_csrf" type="hidden">';
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const csrf002 = result.vulnerabilities.find((v) => v.ruleId === 'SCG-AUF-CSRF-002');
    expect(csrf002).toBeDefined();
  });

  it('does not flag CSRF token with actual value', () => {
    const code = '<input type="hidden" name="_csrf" value="abc123token">';
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const csrf002 = result.vulnerabilities.find((v) => v.ruleId === 'SCG-AUF-CSRF-002');
    expect(csrf002).toBeUndefined();
  });
});

describe('SCG-AUF-OAUTH-001: OAuth State Validation', () => {
  it('detects callback without state validation', () => {
    const code = "app.get('/auth/callback', (req, res) => { const authCode = req.query.code; exchangeToken(authCode); });";
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const oauth = result.vulnerabilities.find((v) => v.ruleId === 'SCG-AUF-OAUTH-001');
    expect(oauth).toBeDefined();
  });

  it('does not flag callback with state validation', () => {
    const code = `app.get('/auth/callback', (req, res) => {
      const { code, state } = req.query;
      if (state !== req.session.state) return res.status(403).end();
      exchangeToken(code);
    });`;
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const oauth = result.vulnerabilities.find((v) => v.ruleId === 'SCG-AUF-OAUTH-001');
    expect(oauth).toBeUndefined();
  });
});

describe('XSS innerHTML safe patterns', () => {
  it('does not flag innerHTML with static SVG literal', () => {
    const code = "icon.innerHTML = '<svg viewBox=\"0 0 24 24\"></svg>';";
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const xss = result.vulnerabilities.find((v) => v.ruleId === 'SCG-XSS-DOM-001');
    expect(xss).toBeUndefined();
  });

  it('does not flag innerHTML with static <i> tag', () => {
    const code = "el.innerHTML = '<i class=\"fa-solid fa-eye\"></i>';";
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const xss = result.vulnerabilities.find((v) => v.ruleId === 'SCG-XSS-DOM-001');
    expect(xss).toBeUndefined();
  });

  it('does not flag innerHTML with DOMPurify.sanitize', () => {
    const code = 'el.innerHTML = DOMPurify.sanitize(content);';
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const xss = result.vulnerabilities.find((v) => v.ruleId === 'SCG-XSS-DOM-001');
    expect(xss).toBeUndefined();
  });

  it('still flags innerHTML with dynamic variable', () => {
    const code = 'el.innerHTML = userInput;';
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const xss = result.vulnerabilities.find((v) => v.ruleId === 'SCG-XSS-DOM-001');
    expect(xss).toBeDefined();
  });

  it('does not flag innerHTML empty string reset', () => {
    const code = "list.innerHTML = '';";
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const xss = result.vulnerabilities.find((v) => v.ruleId === 'SCG-XSS-DOM-001');
    expect(xss).toBeUndefined();
  });
});
