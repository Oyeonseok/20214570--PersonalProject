import { describe, it, expect } from 'vitest';
import { validateSecurityClaims } from '../../../src/tools/generate-secure.js';

describe('validateSecurityClaims', () => {
  it('marks XSS as implemented when textContent is used', () => {
    const code = 'element.textContent = userInput;';
    const claims = ['[XSS 방지] textContent로 삽입'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('implemented');
  });

  it('marks CSRF as implemented when fetchCsrfToken exists', () => {
    const code = 'async function fetchCsrfToken() { fetch("/api/csrf-token") }';
    const claims = ['[CSRF] 서버 동적 CSRF 토큰 발급'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('implemented');
  });

  it('marks CSRF as partial when only _csrf field exists', () => {
    const code = '<input name="_csrf" value="">';
    const claims = ['[CSRF] CSRF 토큰 포함'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('partial');
  });

  it('marks Rate Limiting as partial with client-only implementation', () => {
    const code = 'const loginAttempts = { count: 0 }; const MAX_ATTEMPTS = 5;';
    const claims = ['[Rate Limiting] 15분/5회 로그인 제한'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('partial');
  });

  it('marks Rate Limiting as implemented with express-rate-limit', () => {
    const code = "import rateLimit from 'express-rate-limit'; const limiter = rateLimit({ windowMs: 900000 });";
    const claims = ['[Rate Limiting] 서버측 Rate Limiting'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('implemented');
  });

  it('marks OAuth state as partial with client-only sessionStorage', () => {
    const code = "sessionStorage.setItem('oauth_state', state);";
    const claims = ['[OAuth] OAuth state 파라미터 생성'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('partial');
  });

  it('marks server headers as partial when only meta tags exist', () => {
    const code = '<meta http-equiv="X-Frame-Options" content="DENY">';
    const claims = ['[서버 헤더] 보안 응답 헤더 설정'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('partial');
  });

  it('marks server headers as implemented with res.setHeader', () => {
    const code = "res.setHeader('X-Frame-Options', 'DENY');";
    const claims = ['[서버 헤더] 보안 응답 헤더 설정'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('implemented');
  });

  it('handles multiple claims correctly', () => {
    const code = 'element.textContent = x; const loginAttempts = {count:0};';
    const claims = [
      '[XSS] textContent 사용',
      '[Rate Limiting] 로그인 제한',
    ];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('implemented');
    expect(result[1].status).toBe('partial');
  });

  it('returns implemented for unmatched claim keywords', () => {
    const code = 'const x = 1;';
    const claims = ['[기타] 특수한 보안 조치'];
    const result = validateSecurityClaims(code, claims);
    expect(result[0].status).toBe('implemented');
  });
});
