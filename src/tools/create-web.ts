import { z } from 'zod';
import { handleSecureDevelop } from './secure-develop.js';
import { handleGenerateSecure } from './generate-secure.js';

export const createWebSchema = z.object({
  feature: z
    .string()
    .describe("만들 웹 페이지 또는 기능 (예: '로그인 페이지', '게시판', '회원가입', '댓글', '파일 업로드', '검색 페이지', 'REST API')"),
  language: z
    .enum(['html', 'javascript', 'typescript', 'python', 'java'])
    .default('html')
    .describe("언어. 웹 페이지는 'html', 백엔드 API는 'typescript'"),
  framework: z
    .string()
    .optional()
    .describe('프레임워크 (예: express, react, nextjs, fastapi)'),
});

export type CreateWebInput = z.infer<typeof createWebSchema>;

export function handleCreateWeb(input: CreateWebInput) {
  const guideResult = handleSecureDevelop({
    feature: input.feature,
    language: input.language === 'html' || input.language === 'javascript'
      ? 'javascript'
      : input.language as 'typescript' | 'python' | 'java',
    framework: input.framework,
    includes_frontend: true,
  });

  const codeResult = handleGenerateSecure({
    task: input.feature,
    language: input.language,
    framework: input.framework,
  });

  const guideText = guideResult.content[0].text;
  const codeText = codeResult.content[0].text;

  const combined = [
    guideText,
    '',
    '---',
    '',
    codeText,
  ].join('\n');

  return {
    content: [{ type: 'text' as const, text: combined }],
  };
}
