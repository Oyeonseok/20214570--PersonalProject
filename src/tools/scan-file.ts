import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanCode } from '../engine/scanner.js';
import { detectLanguageFromExtension } from '../utils/language-detector.js';
import type { Severity } from '../types/index.js';

export const scanFileSchema = z.object({
  file_path: z.string().describe('스캔할 파일의 절대/상대 경로'),
  rule_sets: z
    .array(z.string())
    .default(['owasp', 'cwe-top25'])
    .describe('적용할 룰셋 목록'),
  exclude_rules: z.array(z.string()).default([]).describe('제외할 룰 ID 목록'),
  severity_threshold: z
    .enum(['critical', 'high', 'medium', 'low', 'info'])
    .default('low')
    .describe('리포트할 최소 심각도'),
});

export type ScanFileInput = z.infer<typeof scanFileSchema>;

export function handleScanFile(input: ScanFileInput) {
  const filePath = resolve(input.file_path);
  let code: string;

  try {
    code = readFileSync(filePath, 'utf-8');
  } catch (err) {
    return {
      content: [
        {
          type: 'text' as const,
          text: `❌ 파일을 읽을 수 없습니다: ${filePath}\n에러: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
    };
  }

  const language = detectLanguageFromExtension(filePath);

  if (language === 'unknown') {
    return {
      content: [
        {
          type: 'text' as const,
          text: `⚠️ 지원하지 않는 파일 형식입니다: ${filePath}\n지원 언어: JavaScript, TypeScript, Python, Java`,
        },
      ],
    };
  }

  const maxSize = 500 * 1024;
  if (Buffer.byteLength(code, 'utf-8') > maxSize) {
    return {
      content: [
        {
          type: 'text' as const,
          text: `⚠️ 파일 크기가 너무 큽니다 (${Math.round(Buffer.byteLength(code, 'utf-8') / 1024)}KB). 최대 ${maxSize / 1024}KB까지 지원합니다.`,
        },
      ],
    };
  }

  const result = scanCode(code, {
    language,
    filePath,
    severityThreshold: input.severity_threshold as Severity,
    excludeRules: input.exclude_rules,
  });

  const totalLines = code.split('\n').length;
  const lines: string[] = [];

  lines.push(`## 📄 파일 보안 스캔: ${filePath}`);
  lines.push('');
  lines.push(`| 항목 | 값 |`);
  lines.push(`|---|---|`);
  lines.push(`| 파일 | \`${filePath}\` |`);
  lines.push(`| 언어 | ${result.language} |`);
  lines.push(`| 코드 줄 수 | ${totalLines} |`);
  lines.push(`| 발견 이슈 | **${result.summary.totalIssues}개** |`);
  lines.push(`| 위험 점수 | **${result.summary.riskScore}/10** |`);
  lines.push('');

  if (result.summary.totalIssues === 0) {
    lines.push('### ✅ 취약점이 발견되지 않았습니다.');
  } else {
    lines.push(`| 심각도 | 수량 |`);
    lines.push(`|---|---|`);
    if (result.summary.critical > 0) lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
    if (result.summary.high > 0) lines.push(`| 🟠 High | ${result.summary.high} |`);
    if (result.summary.medium > 0) lines.push(`| 🟡 Medium | ${result.summary.medium} |`);
    if (result.summary.low > 0) lines.push(`| 🔵 Low | ${result.summary.low} |`);
    lines.push('');

    for (const vuln of result.vulnerabilities) {
      const badge = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' }[vuln.severity];
      lines.push(`### ${badge} [Line ${vuln.location.startLine}] ${vuln.titleKo}`);
      lines.push(`- **${vuln.ruleId}** | ${vuln.cweId} | ${vuln.severity.toUpperCase()}`);
      lines.push(`- 코드: \`${vuln.matchedCode}\``);
      lines.push(`- ${vuln.descriptionKo}`);
      lines.push(`- **수정**: ${vuln.remediation.descriptionKo}`);
      lines.push('');
    }
  }

  if (result.suggestions.length > 0) {
    lines.push('## 💡 권장사항');
    for (const s of result.suggestions) {
      lines.push(`- ${s}`);
    }
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
    structuredResult: result,
  };
}
