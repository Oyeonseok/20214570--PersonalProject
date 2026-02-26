import { z } from 'zod';
import { handleScanCode } from './scan-code.js';
import { handleAuditConfigContent } from './audit-config.js';

export const reviewCodeSchema = z.object({
  code: z.string().describe('검토할 소스 코드 또는 설정 파일 내용'),
  language: z
    .enum(['javascript', 'typescript', 'python', 'java'])
    .optional()
    .describe('프로그래밍 언어 (미지정 시 자동 감지)'),
  context: z
    .enum(['frontend', 'backend', 'fullstack', 'api', 'config'])
    .optional()
    .describe('코드 컨텍스트'),
  framework: z.string().optional().describe('프레임워크 (예: express, react)'),
});

export type ReviewCodeInput = z.infer<typeof reviewCodeSchema>;

export function handleReviewCode(input: ReviewCodeInput) {
  const isConfig = input.context === 'config' ||
    /^\s*(FROM |version:|services:|[A-Z_]+=)/m.test(input.code);

  if (isConfig) {
    const configType = detectConfigType(input.code);
    return handleAuditConfigContent(input.code, configType);
  }

  return handleScanCode({
    code: input.code,
    language: input.language,
    context: input.context,
    framework: input.framework,
    severity_threshold: 'low',
  });
}

function detectConfigType(content: string): string {
  if (/^\s*FROM /m.test(content)) return 'dockerfile';
  if (/^\s*services:/m.test(content)) return 'docker-compose';
  if (/^[A-Z_]+=.*/m.test(content)) return 'env';
  return 'env';
}
