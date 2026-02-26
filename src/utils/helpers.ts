import { randomUUID } from 'node:crypto';
import type { Severity, ScanSummary, Vulnerability } from '../types/index.js';

export function generateScanId(): string {
  return randomUUID();
}

export function nowISO(): string {
  return new Date().toISOString();
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export function calculateRiskScore(vulnerabilities: Vulnerability[]): number {
  if (vulnerabilities.length === 0) return 0;

  const weights: Record<Severity, number> = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1.5,
    info: 0.5,
  };

  let total = 0;
  for (const vuln of vulnerabilities) {
    const base = weights[vuln.severity];
    const confidenceMultiplier = vuln.confidence === 'high' ? 1 : vuln.confidence === 'medium' ? 0.7 : 0.4;
    total += base * confidenceMultiplier;
  }

  return Math.min(10, Math.round(total * 10) / 10);
}

export function buildSummary(vulnerabilities: Vulnerability[]): ScanSummary {
  const summary: ScanSummary = {
    totalIssues: vulnerabilities.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    riskScore: 0,
  };

  for (const vuln of vulnerabilities) {
    summary[vuln.severity]++;
  }
  summary.riskScore = calculateRiskScore(vulnerabilities);

  return summary;
}

export function truncateCode(code: string, maxLength: number = 200): string {
  if (code.length <= maxLength) return code;
  return code.slice(0, maxLength) + '...';
}
