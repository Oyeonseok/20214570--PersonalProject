import { describe, it, expect } from 'vitest';
import {
  ALL_RULES,
  getRuleById,
  getRulesByLanguage,
  getRulesBySeverity,
  getRulesByCwe,
  getRulesForFramework,
} from '../../../src/rules/index.js';

describe('ALL_RULES', () => {
  it('has rules loaded', () => {
    expect(ALL_RULES.length).toBeGreaterThan(0);
  });

  it('every rule has required fields', () => {
    for (const rule of ALL_RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.title).toBeTruthy();
      expect(rule.titleKo).toBeTruthy();
      expect(rule.severity).toMatch(/^(critical|high|medium|low|info)$/);
      expect(rule.confidence).toMatch(/^(high|medium|low)$/);
      expect(rule.cweId).toMatch(/^CWE-\d+$/);
      expect(rule.patterns.length).toBeGreaterThan(0);
      expect(rule.languages.length).toBeGreaterThan(0);
      expect(rule.remediation).toBeDefined();
      expect(rule.remediation.description).toBeTruthy();
      expect(rule.remediation.descriptionKo).toBeTruthy();
    }
  });

  it('every rule has unique ID', () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every rule pattern has a valid regex', () => {
    for (const rule of ALL_RULES) {
      for (const pattern of rule.patterns) {
        expect(pattern.regex).toBeInstanceOf(RegExp);
        if (pattern.negativeRegex) {
          expect(pattern.negativeRegex).toBeInstanceOf(RegExp);
        }
      }
    }
  });
});

describe('getRuleById', () => {
  it('finds existing rule', () => {
    const firstRule = ALL_RULES[0];
    expect(getRuleById(firstRule.id)).toBe(firstRule);
  });

  it('returns undefined for non-existent rule', () => {
    expect(getRuleById('NONEXISTENT-001')).toBeUndefined();
  });
});

describe('getRulesByLanguage', () => {
  it('returns JavaScript rules', () => {
    const jsRules = getRulesByLanguage('javascript');
    expect(jsRules.length).toBeGreaterThan(0);
    expect(jsRules.every((r) => r.languages.includes('javascript'))).toBe(true);
  });

  it('returns Python rules', () => {
    const pyRules = getRulesByLanguage('python');
    expect(pyRules.length).toBeGreaterThan(0);
  });

  it('returns empty for unknown language', () => {
    const rules = getRulesByLanguage('cobol');
    expect(rules.length).toBe(0);
  });
});

describe('getRulesBySeverity', () => {
  it('returns only matching severity', () => {
    const critical = getRulesBySeverity('critical');
    expect(critical.every((r) => r.severity === 'critical')).toBe(true);
  });
});

describe('getRulesByCwe', () => {
  it('returns rules for CWE-79 (XSS)', () => {
    const xss = getRulesByCwe('CWE-79');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.every((r) => r.cweId === 'CWE-79')).toBe(true);
  });
});

describe('getRulesForFramework', () => {
  it('returns rules applicable to express', () => {
    const expressRules = getRulesForFramework('express');
    expect(expressRules.length).toBeGreaterThan(0);
  });

  it('includes framework-agnostic rules', () => {
    const rules = getRulesForFramework('any-framework');
    const agnostic = ALL_RULES.filter((r) => !r.frameworks || r.frameworks.length === 0);
    for (const rule of agnostic) {
      expect(rules).toContain(rule);
    }
  });
});
