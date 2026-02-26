import { describe, it, expect } from 'vitest';
import {
  getKnowledgeByCwe,
  getKnowledgeByCategory,
  getAllCategories,
  getAllKnowledge,
  findKnowledgeForCweIds,
} from '../../../src/knowledge/portswigger-remediation.js';

describe('PortSwigger Remediation KB', () => {
  it('getAllCategories returns 15 categories', () => {
    const categories = getAllCategories();
    expect(categories.length).toBe(15);
  });

  it('getAllKnowledge returns all entries', () => {
    const all = getAllKnowledge();
    expect(all.length).toBe(15);
  });

  it('getKnowledgeByCwe finds SQL injection for CWE-89', () => {
    const kb = getKnowledgeByCwe('CWE-89');
    expect(kb).toBeDefined();
    expect(kb!.category).toBe('sql-injection');
    expect(kb!.preventionTechniques.length).toBeGreaterThan(0);
    expect(kb!.portswiggerUrl).toContain('portswigger.net');
  });

  it('getKnowledgeByCwe finds XSS for CWE-79', () => {
    const kb = getKnowledgeByCwe('CWE-79');
    expect(kb).toBeDefined();
    expect(kb!.category).toBe('xss');
  });

  it('getKnowledgeByCwe finds CSRF for CWE-352', () => {
    const kb = getKnowledgeByCwe('CWE-352');
    expect(kb).toBeDefined();
    expect(kb!.category).toBe('csrf');
  });

  it('getKnowledgeByCwe finds prototype pollution for CWE-1321', () => {
    const kb = getKnowledgeByCwe('CWE-1321');
    expect(kb).toBeDefined();
    expect(kb!.category).toBe('prototype-pollution');
  });

  it('getKnowledgeByCwe returns undefined for unknown CWE', () => {
    expect(getKnowledgeByCwe('CWE-99999')).toBeUndefined();
  });

  it('getKnowledgeByCategory finds jwt-attacks', () => {
    const kb = getKnowledgeByCategory('jwt-attacks');
    expect(kb).toBeDefined();
    expect(kb!.cweIds).toContain('CWE-345');
  });

  it('findKnowledgeForCweIds returns unique results', () => {
    const results = findKnowledgeForCweIds(['CWE-89', 'CWE-564', 'CWE-79']);
    expect(results.length).toBe(2);
    expect(results.map((r) => r.category)).toContain('sql-injection');
    expect(results.map((r) => r.category)).toContain('xss');
  });

  it('every entry has required fields', () => {
    for (const kb of getAllKnowledge()) {
      expect(kb.category).toBeTruthy();
      expect(kb.cweIds.length).toBeGreaterThan(0);
      expect(kb.title).toBeTruthy();
      expect(kb.titleKo).toBeTruthy();
      expect(kb.attackMechanism).toBeTruthy();
      expect(kb.attackMechanismKo).toBeTruthy();
      expect(kb.preventionTechniques.length).toBeGreaterThan(0);
      expect(kb.preventionTechniquesKo.length).toBeGreaterThan(0);
      expect(kb.commonMistakes.length).toBeGreaterThan(0);
      expect(kb.commonMistakesKo.length).toBeGreaterThan(0);
      expect(kb.secureCodeExample).toBeTruthy();
      expect(kb.portswiggerUrl).toContain('portswigger.net');
    }
  });
});
