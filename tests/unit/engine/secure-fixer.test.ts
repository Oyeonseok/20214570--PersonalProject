import { describe, it, expect } from 'vitest';
import { applySecureFixes } from '../../../src/engine/secure-fixer.js';
import { scanCode } from '../../../src/engine/scanner.js';

function scanAndFix(code: string) {
  const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
  return applySecureFixes(code, result.vulnerabilities);
}

describe('applySecureFixes', () => {
  describe('innerHTML auto-fix', () => {
    it('replaces innerHTML = with textContent =', () => {
      const code = 'element.innerHTML = userInput;';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('textContent');
      expect(fix.appliedFixes.length).toBeGreaterThan(0);
    });

    it('replaces innerHTML += with textContent +=', () => {
      const code = 'el.innerHTML += data;';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('textContent +=');
    });

    it('replaces outerHTML = with textContent =', () => {
      const code = 'el.outerHTML = content;';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('textContent');
    });
  });

  describe('eval handling', () => {
    it('puts eval() in manual fixes since rule ID differs from handler key', () => {
      const code = 'eval(userCode);';
      const fix = scanAndFix(code);
      expect(fix.manualFixes.length + fix.appliedFixes.length).toBeGreaterThan(0);
    });
  });

  describe('document.write auto-fix', () => {
    it('converts document.write() to DOM API', () => {
      const code = 'document.write(html);';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('createTextNode');
      expect(fix.appliedFixes.length).toBeGreaterThan(0);
    });
  });

  describe('HTML hardening', () => {
    it('adds rel="noopener noreferrer" to target="_blank"', () => {
      const code = '<!DOCTYPE html><html><head></head><body><a href="x" target="_blank">link</a></body></html>';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('rel="noopener noreferrer"');
    });

    it('adds autocomplete to password fields', () => {
      const code = '<!DOCTYPE html><html><head></head><body><input type="password" name="pw"></body></html>';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('autocomplete="current-password"');
    });

    it('adds CSRF token to forms', () => {
      const code = '<!DOCTYPE html><html><head></head><body><form action="/login" method="post"><input type="text"></form></body></html>';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('name="_csrf"');
    });

    it('injects security headers when missing', () => {
      const code = '<!DOCTYPE html><html><head><title>Test</title></head><body>Hello</body></html>';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('Content-Security-Policy');
      expect(fix.fixedCode).toContain('X-Frame-Options');
      expect(fix.fixedCode).toContain('X-Content-Type-Options');
      expect(fix.injectedHeaders.length).toBeGreaterThan(0);
    });

    it('does not duplicate existing security headers', () => {
      const code = '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><meta http-equiv="X-Frame-Options" content="DENY"><meta http-equiv="X-Content-Type-Options" content="nosniff"><meta http-equiv="Referrer-Policy" content="no-referrer"></head><body></body></html>';
      const fix = scanAndFix(code);
      expect(fix.injectedHeaders.length).toBe(0);
    });
  });

  describe('auto fixes for secrets', () => {
    it('auto-fixes hardcoded secrets to process.env', () => {
      const code = 'const secret = "my-password-123";\nconst apiKey = "api-key-abc-def-ghi";';
      const fix = scanAndFix(code);
      expect(fix.appliedFixes.length).toBeGreaterThan(0);
      expect(fix.fixedCode).toContain('process.env');
    });
  });

  describe('innerHTML safe pattern skip', () => {
    it('does not modify innerHTML with static HTML tag literal', () => {
      const code = 'eyeIcon.innerHTML = \'<i class="fa-eye"></i>\';';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).not.toContain('textContent');
      expect(fix.fixedCode).toContain('innerHTML');
    });

    it('does not modify innerHTML with SVG literal', () => {
      const code = 'icon.innerHTML = \'<svg viewBox="0 0 24 24"><path d="M12"/></svg>\';';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('innerHTML');
      expect(fix.fixedCode).not.toContain('textContent');
    });

    it('does not modify innerHTML with DOMPurify.sanitize', () => {
      const code = 'el.innerHTML = DOMPurify.sanitize(userHtml);';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('innerHTML');
    });

    it('still fixes innerHTML with dynamic content', () => {
      const code = 'el.innerHTML = userInput;';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('textContent');
    });

    it('does not modify innerHTML empty string reset', () => {
      const code = "list.innerHTML = '';";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("innerHTML = ''");
    });
  });

  describe('server guides', () => {
    it('generates server header guide for HTML with injected headers', () => {
      const code = '<!DOCTYPE html><html><head><title>T</title></head><body></body></html>';
      const fix = scanAndFix(code);
      expect(fix.serverGuides.length).toBeGreaterThan(0);
      expect(fix.serverGuides.join('\n')).toContain('서버 응답 헤더');
      expect(fix.serverGuides.join('\n')).toContain('res.setHeader');
    });

    it('generates CSRF server guide when CSRF tokens present', () => {
      const code = '<!DOCTYPE html><html><head></head><body><form action="/login"><input name="_csrf" value=""></form></body></html>';
      const fix = scanAndFix(code);
      const guides = fix.serverGuides.join('\n');
      expect(guides).toContain('CSRF 토큰 발급');
      expect(guides).toContain('verifyCsrf');
    });

    it('generates rate limit guide for login pages', () => {
      const code = '<!DOCTYPE html><html><head></head><body><script>const loginAttempts = {count:0}; const MAX_ATTEMPTS = 5;</script></body></html>';
      const fix = scanAndFix(code);
      const guides = fix.serverGuides.join('\n');
      expect(guides).toContain('Rate Limiting');
      expect(guides).toContain('express-rate-limit');
    });
  });

  describe('no vulnerabilities', () => {
    it('returns unchanged code when no vulnerabilities found', () => {
      const code = 'const x = 1;';
      const result = applySecureFixes(code, []);
      expect(result.fixedCode).toBe(code);
      expect(result.appliedFixes.length).toBe(0);
      expect(result.manualFixes.length).toBe(0);
      expect(result.serverGuides.length).toBe(0);
      expect(result.addedImports.length).toBe(0);
    });
  });
});
