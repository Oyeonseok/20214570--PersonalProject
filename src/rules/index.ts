import type { SecurityRule } from '../types/index.js';
import { injectionRules } from './injection-rules.js';
import { xssRules } from './xss-rules.js';
import { authRules } from './auth-rules.js';
import { cryptoRules } from './crypto-rules.js';
import { configRules } from './config-rules.js';
import { serverRules } from './server-rules.js';

export const ALL_RULES: SecurityRule[] = [
  ...injectionRules,
  ...xssRules,
  ...authRules,
  ...cryptoRules,
  ...configRules,
  ...serverRules,
];

export function getRuleById(ruleId: string): SecurityRule | undefined {
  return ALL_RULES.find((r) => r.id === ruleId);
}

export function getRulesByLanguage(language: string): SecurityRule[] {
  return ALL_RULES.filter((r) => r.languages.includes(language as any));
}

export function getRulesForFramework(framework: string): SecurityRule[] {
  return ALL_RULES.filter(
    (r) => !r.frameworks || r.frameworks.length === 0 || r.frameworks.includes(framework)
  );
}
