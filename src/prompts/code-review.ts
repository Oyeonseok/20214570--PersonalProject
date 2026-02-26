import { handleCreateWeb } from '../tools/create-web.js';

// ─── 핵심 프롬프트: /secure_build (강제 도구 호출) ───

export const SECURE_BUILD_PROMPT = {
  name: 'secure_build',
  description: '시큐어코딩이 적용된 웹 페이지/기능을 만듭니다. 로그인, 게시판, 회원가입, 댓글, 파일 업로드 등.',
  arguments: [
    {
      name: 'feature',
      description: "만들 기능 (예: '로그인 페이지', '게시판', '회원가입 폼')",
      required: true,
    },
    {
      name: 'language',
      description: "언어: html, typescript, javascript, python (기본: html)",
      required: false,
    },
  ],
};

export function buildSecureBuildMessages(args: Record<string, string>) {
  const feature = args.feature ?? '웹 페이지';
  const language = (args.language ?? 'html') as 'html' | 'javascript' | 'typescript' | 'python' | 'java';

  const toolResult = handleCreateWeb({ feature, language });
  const secureGuide = toolResult.content[0].text;

  return [
    {
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: `아래는 "${feature}" 기능의 시큐어코딩 가이드와 보안이 적용된 코드 템플릿입니다.

이 가이드의 모든 보안 체크리스트를 적용하여 "${feature}" 코드를 완성해주세요.
가이드에 있는 흔한 보안 실수는 절대 하지 마세요.
코드 템플릿이 제공된 경우, 해당 코드를 기반으로 UI를 예쁘게 만들어주세요.

---

${secureGuide}`,
      },
    },
  ];
}

// ─── 보안 코드 리뷰 프롬프트 ───

export const SECURITY_CODE_REVIEW_PROMPT = {
  name: 'security_code_review',
  description: '코드의 보안 취약점을 전문가 수준으로 리뷰합니다.',
  arguments: [
    {
      name: 'code',
      description: '리뷰할 코드',
      required: true,
    },
    {
      name: 'language',
      description: '프로그래밍 언어',
      required: false,
    },
    {
      name: 'context',
      description: '코드 용도 (예: 로그인 API, 결제 처리)',
      required: false,
    },
  ],
};

export function buildCodeReviewMessages(args: Record<string, string>) {
  const code = args.code ?? '';
  const language = args.language ?? '자동 감지';
  const context = args.context ?? '일반';

  return [
    {
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: `당신은 20년 경력의 웹 보안 전문가입니다.

아래 ${language} 코드를 보안 관점에서 리뷰하세요.
코드 용도: ${context}

먼저 review_code 도구를 사용하여 자동 취약점 탐지를 실행한 후,
결과를 분석하고 추가 보안 이슈를 함께 보고하세요.

각 취약점에 대해:
- 심각도 (Critical/High/Medium/Low)
- 위치 (라인 번호)
- 취약점 설명
- 공격 시나리오
- 수정 코드

\`\`\`${language}
${code}
\`\`\``,
      },
    },
  ];
}

// ─── 위협 모델링 프롬프트 ───

export const THREAT_MODELING_PROMPT = {
  name: 'threat_modeling',
  description: 'STRIDE 프레임워크 기반 위협 분석',
  arguments: [
    {
      name: 'system_description',
      description: '시스템/아키텍처 설명',
      required: true,
    },
    {
      name: 'assets',
      description: '보호해야 할 자산 목록',
      required: false,
    },
  ],
};

export function buildThreatModelingMessages(args: Record<string, string>) {
  const systemDesc = args.system_description ?? '';
  const assets = args.assets ?? '사용자 데이터, 인증정보';

  return [
    {
      role: 'user' as const,
      content: {
        type: 'text' as const,
        text: `STRIDE 프레임워크로 위협 모델링을 수행하세요.

[시스템] ${systemDesc}
[보호 자산] ${assets}

각 STRIDE 카테고리별로:
1. 위협 시나리오
2. 영향도/발생 가능성
3. 권장 대응 방안`,
      },
    },
  ];
}
