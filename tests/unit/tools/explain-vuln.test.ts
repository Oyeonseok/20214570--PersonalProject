import { describe, it, expect } from 'vitest';
import { handleExplainVuln } from '../../../src/tools/explain-vuln.js';

describe('handleExplainVuln', () => {
  it('explains a known CWE ID', () => {
    const result = handleExplainVuln({
      vulnerability_id: 'CWE-89',
      detail_level: 'beginner',
      include_demo: true,
    });
    expect(result.content[0].text).toContain('SQL');
    expect(result.content[0].text).toContain('수정 방법');
  });

  it('explains by rule ID', () => {
    const result = handleExplainVuln({
      vulnerability_id: 'SCG-XSS-DOM-001',
      detail_level: 'intermediate',
      include_demo: false,
    });
    expect(result.content[0].text).toContain('innerHTML');
  });

  it('returns error for unknown ID', () => {
    const result = handleExplainVuln({
      vulnerability_id: 'UNKNOWN-999',
      detail_level: 'beginner',
      include_demo: false,
    });
    expect(result.content[0].text).toContain('찾을 수 없습니다');
  });

  it('includes attack demo when requested', () => {
    const result = handleExplainVuln({
      vulnerability_id: 'CWE-79',
      detail_level: 'intermediate',
      include_demo: true,
    });
    expect(result.content[0].text).toContain('공격 시나리오');
  });

  it('handles code_context parameter', () => {
    const result = handleExplainVuln({
      vulnerability_id: 'CWE-89',
      code_context: 'db.query("SELECT * FROM users WHERE id = " + id)',
      detail_level: 'intermediate',
      include_demo: false,
    });
    expect(result.content[0].text).toContain('코드 분석');
  });
});
