import { describe, it, expect } from 'vitest';
import { handleSecureDevelop } from '../../../src/tools/secure-develop.js';

describe('handleSecureDevelop', () => {
  it('returns guide for login feature', () => {
    const result = handleSecureDevelop({
      feature: '로그인 페이지',
      language: 'typescript',
      includes_frontend: true,
    });
    const text = result.content[0].text;
    expect(text).toContain('보안 위협');
    expect(text).toContain('체크리스트');
    expect(text).toContain('프론트엔드');
  });

  it('returns guide for board feature', () => {
    const result = handleSecureDevelop({
      feature: '게시판',
      language: 'javascript',
      includes_frontend: false,
    });
    expect(result.content[0].text).toContain('게시판');
  });

  it('returns guide for unrecognized features', () => {
    const result = handleSecureDevelop({
      feature: 'quantum teleportation module',
      language: 'typescript',
      includes_frontend: false,
    });
    expect(result.content[0].text).toContain('시큐어 개발 가이드');
  });

  it('includes frontend checklist when feature mentions page', () => {
    const result = handleSecureDevelop({
      feature: '회원가입 페이지',
      language: 'typescript',
      includes_frontend: false,
    });
    expect(result.content[0].text).toContain('프론트엔드');
  });
});
