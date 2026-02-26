import { describe, it, expect } from 'vitest';
import { handleReviewCode } from '../../../src/tools/review-code.js';

describe('handleReviewCode', () => {
  it('scans code when context is not config', () => {
    const result = handleReviewCode({
      code: 'element.innerHTML = data;',
      language: 'javascript',
      context: 'frontend',
    });
    expect(result.content[0].text).toContain('보안 스캔');
  });

  it('audits config when context is config', () => {
    const result = handleReviewCode({
      code: 'DB_PASSWORD=password\nDEBUG=true',
      context: 'config',
    });
    expect(result.content[0].text).toContain('보안 감사');
  });

  it('auto-detects Dockerfile content as config', () => {
    const result = handleReviewCode({
      code: 'FROM node:latest\nCOPY . .\nUSER root',
    });
    expect(result.content[0].text).toContain('보안 감사');
  });

  it('auto-detects env content as config', () => {
    const result = handleReviewCode({
      code: 'SECRET_KEY=abc\nNODE_ENV=development',
    });
    expect(result.content[0].text).toContain('보안 감사');
  });
});
