import { describe, it, expect } from 'vitest';
import {
  generateScanId,
  nowISO,
  severityToNumber,
  compareSeverity,
  meetsThreshold,
  calculateRiskScore,
  buildSummary,
  truncateCode,
} from '../../../src/utils/helpers.js';
import type { Vulnerability, Severity } from '../../../src/types/index.js';

function makeVuln(severity: Severity, confidence: 'high' | 'medium' | 'low' = 'high'): Vulnerability {
  return {
    id: 'V-001',
    ruleId: 'SCG-TEST',
    title: 'Test',
    titleKo: '테스트',
    severity,
    confidence,
    category: 'test',
    cweId: 'CWE-79',
    location: { startLine: 1, endLine: 1 },
    matchedCode: 'test',
    description: 'test',
    descriptionKo: '테스트',
    remediation: { description: '', descriptionKo: '', references: [] },
  };
}

describe('generateScanId', () => {
  it('returns a valid UUID string', () => {
    const id = generateScanId();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('returns unique values', () => {
    const ids = new Set(Array.from({ length: 10 }, () => generateScanId()));
    expect(ids.size).toBe(10);
  });
});

describe('nowISO', () => {
  it('returns a valid ISO 8601 string', () => {
    const iso = nowISO();
    expect(new Date(iso).toISOString()).toBe(iso);
  });
});

describe('severityToNumber', () => {
  it('maps severity levels correctly', () => {
    expect(severityToNumber('critical')).toBe(5);
    expect(severityToNumber('high')).toBe(4);
    expect(severityToNumber('medium')).toBe(3);
    expect(severityToNumber('low')).toBe(2);
    expect(severityToNumber('info')).toBe(1);
  });
});

describe('compareSeverity', () => {
  it('orders critical above low', () => {
    expect(compareSeverity('critical', 'low')).toBeLessThan(0);
  });

  it('orders low below critical', () => {
    expect(compareSeverity('low', 'critical')).toBeGreaterThan(0);
  });

  it('returns 0 for same severity', () => {
    expect(compareSeverity('high', 'high')).toBe(0);
  });
});

describe('meetsThreshold', () => {
  it('critical meets any threshold', () => {
    expect(meetsThreshold('critical', 'critical')).toBe(true);
    expect(meetsThreshold('critical', 'info')).toBe(true);
  });

  it('info only meets info threshold', () => {
    expect(meetsThreshold('info', 'info')).toBe(true);
    expect(meetsThreshold('info', 'low')).toBe(false);
    expect(meetsThreshold('info', 'critical')).toBe(false);
  });

  it('medium meets low threshold but not high', () => {
    expect(meetsThreshold('medium', 'low')).toBe(true);
    expect(meetsThreshold('medium', 'high')).toBe(false);
  });
});

describe('calculateRiskScore', () => {
  it('returns 0 for empty array', () => {
    expect(calculateRiskScore([])).toBe(0);
  });

  it('returns score between 0 and 10', () => {
    const vulns = [makeVuln('critical'), makeVuln('high'), makeVuln('medium')];
    const score = calculateRiskScore(vulns);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(10);
  });

  it('higher severity produces higher score', () => {
    const criticalScore = calculateRiskScore([makeVuln('critical')]);
    const lowScore = calculateRiskScore([makeVuln('low')]);
    expect(criticalScore).toBeGreaterThan(lowScore);
  });

  it('higher confidence produces higher score', () => {
    const highConf = calculateRiskScore([makeVuln('high', 'high')]);
    const lowConf = calculateRiskScore([makeVuln('high', 'low')]);
    expect(highConf).toBeGreaterThan(lowConf);
  });
});

describe('buildSummary', () => {
  it('returns zero counts for empty array', () => {
    const summary = buildSummary([]);
    expect(summary.totalIssues).toBe(0);
    expect(summary.critical).toBe(0);
    expect(summary.riskScore).toBe(0);
  });

  it('counts severity levels correctly', () => {
    const vulns = [
      makeVuln('critical'),
      makeVuln('critical'),
      makeVuln('high'),
      makeVuln('medium'),
      makeVuln('low'),
      makeVuln('info'),
    ];
    const summary = buildSummary(vulns);
    expect(summary.totalIssues).toBe(6);
    expect(summary.critical).toBe(2);
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
    expect(summary.low).toBe(1);
    expect(summary.info).toBe(1);
  });
});

describe('truncateCode', () => {
  it('returns short strings unchanged', () => {
    expect(truncateCode('short')).toBe('short');
  });

  it('truncates long strings with ellipsis', () => {
    const long = 'a'.repeat(300);
    const result = truncateCode(long);
    expect(result.length).toBe(203);
    expect(result.endsWith('...')).toBe(true);
  });

  it('respects custom maxLength', () => {
    const result = truncateCode('abcdefgh', 5);
    expect(result).toBe('abcde...');
  });
});
