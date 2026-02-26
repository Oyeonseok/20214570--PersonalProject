import { z } from 'zod';
import { scanCode } from '../engine/scanner.js';
import type { Language, Severity } from '../types/index.js';

export const scanCodeSchema = z.object({
  code: z.string().describe('분석할 소스 코드 스니펫'),
  language: z
    .enum(['javascript', 'typescript', 'python', 'java'])
    .optional()
    .describe('프로그래밍 언어 (미지정 시 자동 감지)'),
  context: z
    .enum(['frontend', 'backend', 'fullstack', 'api', 'config'])
    .optional()
    .describe('코드가 사용되는 컨텍스트'),
  framework: z.string().optional().describe('사용 중인 프레임워크 (예: express, react, nextjs, fastapi)'),
  severity_threshold: z
    .enum(['critical', 'high', 'medium', 'low', 'info'])
    .default('low')
    .describe('리포트할 최소 심각도'),
});

export type ScanCodeInput = z.infer<typeof scanCodeSchema>;

export function handleScanCode(input: ScanCodeInput) {
  const result = scanCode(input.code, {
    language: input.language as Language | undefined,
    framework: input.framework,
    context: input.context,
    severityThreshold: input.severity_threshold as Severity,
  });

  const lines: string[] = [];

  if (result.summary.totalIssues === 0) {
    lines.push('## ✅ 보안 스캔 결과: 취약점 없음');
    lines.push('');
    lines.push(`분석 대상: ${result.language} 코드`);
    lines.push(`분석 모드: Lite (룰 기반 정적 분석)`);
    lines.push('');
    lines.push('현재 룰셋 기준으로 취약점이 발견되지 않았습니다.');
    lines.push('');
    lines.push('> 💡 룰 기반 분석의 한계로, 비즈니스 로직 취약점이나 복잡한 데이터 흐름은 탐지되지 않을 수 있습니다.');
  } else {
    lines.push('## 🔴 보안 스캔 결과');
    lines.push('');
    lines.push(`| 항목 | 값 |`);
    lines.push(`|---|---|`);
    lines.push(`| 총 발견 이슈 | **${result.summary.totalIssues}개** |`);
    lines.push(`| Critical | ${result.summary.critical} |`);
    lines.push(`| High | ${result.summary.high} |`);
    lines.push(`| Medium | ${result.summary.medium} |`);
    lines.push(`| Low | ${result.summary.low} |`);
    lines.push(`| 위험 점수 | **${result.summary.riskScore}/10** |`);
    lines.push('');

    for (const vuln of result.vulnerabilities) {
      const severityEmoji: Record<string, string> = {
        critical: '🔴 CRITICAL',
        high: '🟠 HIGH',
        medium: '🟡 MEDIUM',
        low: '🔵 LOW',
        info: 'ℹ️ INFO',
      };

      lines.push(`### ${severityEmoji[vuln.severity]} - ${vuln.titleKo}`);
      lines.push('');
      lines.push(`- **룰 ID**: ${vuln.ruleId}`);
      lines.push(`- **CWE**: ${vuln.cweId}`);
      lines.push(`- **카테고리**: ${vuln.category}`);
      lines.push(`- **위치**: ${vuln.location.startLine}번째 줄`);
      lines.push(`- **발견 코드**: \`${vuln.matchedCode}\``);
      lines.push('');
      lines.push(`**설명**: ${vuln.descriptionKo}`);
      lines.push('');
      if (vuln.attackScenario) {
        lines.push(`**공격 시나리오**: ${vuln.attackScenario}`);
        lines.push('');
      }
      lines.push(`**수정 방법**: ${vuln.remediation.descriptionKo}`);
      if (vuln.remediation.secureExample) {
        lines.push('');
        lines.push('```');
        lines.push(vuln.remediation.secureExample);
        lines.push('```');
      }
      lines.push('');
      lines.push('---');
      lines.push('');
    }

    if (result.suggestions.length > 0) {
      lines.push('## 💡 추가 권장사항');
      for (const s of result.suggestions) {
        lines.push(`- ${s}`);
      }
    }
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
    structuredResult: result,
  };
}
