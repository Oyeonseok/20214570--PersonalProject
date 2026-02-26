import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { handleAuditConfig, handleAuditConfigContent } from '../../../src/tools/audit-config.js';

const FIXTURES = resolve(__dirname, '../../fixtures');

describe('handleAuditConfig', () => {
  it('detects weak password in .env', () => {
    const result = handleAuditConfig({ file_path: resolve(FIXTURES, 'configs/sample.env') });
    expect(result.content[0].text).toContain('비밀번호');
  });

  it('detects debug mode in .env', () => {
    const result = handleAuditConfig({ file_path: resolve(FIXTURES, 'configs/sample.env') });
    expect(result.content[0].text).toContain('디버그');
  });

  it('detects :latest tag in Dockerfile', () => {
    const result = handleAuditConfig({ file_path: resolve(FIXTURES, 'configs/sample.Dockerfile') });
    expect(result.content[0].text).toContain('latest');
  });

  it('detects root user in Dockerfile', () => {
    const result = handleAuditConfig({ file_path: resolve(FIXTURES, 'configs/sample.Dockerfile') });
    expect(result.content[0].text).toContain('root');
  });

  it('returns error for non-existent file', () => {
    const result = handleAuditConfig({ file_path: '/no/such/.env' });
    expect(result.content[0].text).toContain('❌');
  });
});

describe('handleAuditConfigContent', () => {
  it('audits inline env content', () => {
    const content = 'DB_PASSWORD=password\nDEBUG=true\n';
    const result = handleAuditConfigContent(content, 'env');
    expect(result.content[0].text).toContain('보안 감사');
  });

  it('audits inline Dockerfile content', () => {
    const content = 'FROM node:latest\nUSER root\n';
    const result = handleAuditConfigContent(content, 'dockerfile');
    expect(result.content[0].text).toContain('latest');
  });
});
