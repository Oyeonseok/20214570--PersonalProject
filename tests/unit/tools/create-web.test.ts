import { describe, it, expect } from 'vitest';
import { handleCreateWeb } from '../../../src/tools/create-web.js';

describe('handleCreateWeb', () => {
  it('creates login page guide + code', () => {
    const result = handleCreateWeb({ feature: '로그인 페이지', language: 'html' });
    expect(result.content[0].text).toContain('시큐어 개발 가이드');
    expect(result.content[0].text).toContain('시큐어코딩');
  });

  it('creates board page for TypeScript', () => {
    const result = handleCreateWeb({ feature: '게시판', language: 'typescript', framework: 'express' });
    expect(result.content[0].text).toContain('게시판');
  });

  it('handles unknown features gracefully', () => {
    const result = handleCreateWeb({ feature: 'quantum computing interface', language: 'html' });
    expect(result.content[0].text).toBeTruthy();
  });
});
