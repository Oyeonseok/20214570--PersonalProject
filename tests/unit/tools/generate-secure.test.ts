import { describe, it, expect } from 'vitest';
import { handleGenerateSecure } from '../../../src/tools/generate-secure.js';

describe('handleGenerateSecure', () => {
  it('generates login template for html', () => {
    const result = handleGenerateSecure({
      task: '로그인 페이지',
      language: 'html',
    });
    const text = result.content[0].text;
    expect(text).toContain('시큐어코딩');
    expect(text).toContain('로그인');
  });

  it('generates board template for TypeScript express', () => {
    const result = handleGenerateSecure({
      task: '게시판',
      language: 'typescript',
      framework: 'express',
    });
    expect(result.content[0].text).toContain('코드');
  });

  it('returns generic guide when no template matches', () => {
    const result = handleGenerateSecure({
      task: 'blockchain smart contract',
      language: 'typescript',
    });
    expect(result.content[0].text).toContain('시큐어코딩 가이드');
  });

  it('generates registration template', () => {
    const result = handleGenerateSecure({
      task: '회원가입',
      language: 'typescript',
      framework: 'express',
    });
    expect(result.content[0].text).toContain('bcrypt');
  });
});
