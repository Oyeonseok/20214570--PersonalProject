import { z } from 'zod';

export const secureDevelopSchema = z.object({
  feature: z
    .string()
    .describe("구현할 웹 기능 (예: '게시글 작성 페이지', '회원가입 폼', '댓글 기능', '파일 업로드', '검색', '관리자 대시보드', 'REST API')"),
  language: z
    .enum(['javascript', 'typescript', 'python', 'java'])
    .default('typescript')
    .describe('프로그래밍 언어'),
  framework: z.string().optional().describe('프레임워크 (예: express, react, nextjs, fastapi)'),
  includes_frontend: z.boolean().default(false).describe('프론트엔드 코드 포함 여부'),
});

export type SecureDevelopInput = z.infer<typeof secureDevelopSchema>;

interface FeatureSecurityGuide {
  keywords: string[];
  featureName: string;
  featureNameKo: string;
  threats: string[];
  backendChecklist: string[];
  frontendChecklist: string[];
  requiredMiddleware: string[];
  commonMistakes: string[];
  requiredPackages: { name: string; purpose: string }[];
  dbSchema?: string;
}

const FEATURE_GUIDES: FeatureSecurityGuide[] = [
  {
    keywords: ['게시글', '게시판', '글쓰기', '글 작성', 'post', 'board', 'article', 'write', 'blog', 'CRUD', '게시글 페이지', '게시판 페이지', '글쓰기 페이지'],
    featureName: 'Board / Post CRUD',
    featureNameKo: '게시판 (글쓰기/수정/삭제/조회)',
    threats: [
      'Stored XSS: 게시글 본문에 <script> 삽입 → 다른 사용자 세션 탈취',
      'SQL Injection: 검색/필터 파라미터로 DB 탈취',
      'IDOR: /posts/123 의 ID를 변경하여 타인 글 수정/삭제',
      'CSRF: 사용자 모르게 글 작성/삭제 요청 위조',
      '인증 우회: 미로그인 상태에서 글 작성/수정 가능',
      '대량 요청(DoS): 무한 게시글 생성, 검색 LIMIT 없음',
    ],
    backendChecklist: [
      '✅ 모든 입력을 zod/joi 스키마로 검증 (title: max 200자, content: max 50000자)',
      '✅ HTML 콘텐츠 허용 시 DOMPurify.sanitize()로 XSS 필터링',
      '✅ 모든 SQL 쿼리를 파라미터화 ($1, $2)',
      '✅ 검색 LIKE 쿼리에서 %, _ 와일드카드 이스케이프',
      '✅ 게시글 수정/삭제 시 작성자 본인 확인 (IDOR 방지)',
      '✅ 인증 미들웨어 (authenticate) 필수 적용',
      '✅ 페이지네이션 LIMIT 최대값 제한 (예: 100)',
      '✅ ORDER BY는 허용된 컬럼만 화이트리스트',
      '✅ 에러 응답에 스택 트레이스/DB 에러 미포함',
      '✅ 응답에 불필요한 민감정보 미포함 (password_hash, email 등)',
    ],
    frontendChecklist: [
      '✅ 사용자 입력을 DOM에 삽입 시 textContent 사용 (innerHTML 금지)',
      '✅ React 사용 시 dangerouslySetInnerHTML 대신 DOMPurify 적용',
      '✅ 폼 제출 시 CSRF 토큰 포함',
      '✅ 클라이언트 측 입력 검증 (서버 검증과 별개로 UX용)',
      '✅ 에러 메시지에 서버 내부 정보 표시하지 않기',
      '✅ API 호출 시 인증 토큰 자동 포함 (쿠키 or Authorization 헤더)',
    ],
    requiredMiddleware: [
      'authenticate - JWT/세션 인증 확인',
      'express-rate-limit - 게시글 생성 속도 제한',
      'helmet - 보안 헤더 설정',
      'cors - CORS 제한 (특정 도메인만)',
    ],
    commonMistakes: [
      '❌ const query = `SELECT * FROM posts WHERE title LIKE \'%${search}%\'` → SQL Injection',
      '❌ res.send(`<h1>${post.title}</h1>`) → XSS',
      '❌ 수정 API에서 작성자 확인 없이 UPDATE → IDOR',
      '❌ res.json(err) → 에러 객체 전체 노출',
      '❌ 검색 결과에 LIMIT 없음 → DoS',
      '❌ innerHTML = post.content → Stored XSS',
    ],
    requiredPackages: [
      { name: 'zod', purpose: '입력값 스키마 검증' },
      { name: 'isomorphic-dompurify', purpose: 'HTML XSS 새니타이즈' },
      { name: 'express-rate-limit', purpose: '속도 제한' },
      { name: 'helmet', purpose: '보안 헤더' },
    ],
    dbSchema: `CREATE TABLE posts (
  id SERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  content TEXT NOT NULL,
  category VARCHAR(50) DEFAULT 'general',
  author_id INTEGER NOT NULL REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP
);
CREATE INDEX idx_posts_author ON posts(author_id);
CREATE INDEX idx_posts_created ON posts(created_at DESC);`,
  },

  {
    keywords: ['회원가입', 'register', 'signup', 'sign-up', '가입', '계정', '유저 생성', '회원가입 페이지', '가입 페이지', '가입 폼'],
    featureName: 'User Registration',
    featureNameKo: '회원가입',
    threats: [
      '약한 비밀번호: 1234, password 같은 취약한 비밀번호 허용',
      '계정 열거: "이 이메일은 이미 가입되어 있습니다" → 가입 여부 유출',
      '자동 가입 봇: Rate Limiting 없이 대량 계정 생성',
      'SQL Injection: 가입 데이터로 DB 공격',
      '타이밍 공격: 이메일 존재 여부에 따라 응답 시간 차이',
    ],
    backendChecklist: [
      '✅ 비밀번호 정책: 8자 이상 + 대소문자 + 숫자 + 특수문자',
      '✅ bcrypt(12 rounds) 이상으로 비밀번호 해싱',
      '✅ 이메일 소문자 정규화 (중복 가입 방지)',
      '✅ 타이밍 공격 방지: 이메일 중복 시에도 bcrypt.hash 실행',
      '✅ Rate Limiting: 시간당 5회 가입 제한',
      '✅ 입력 검증: 이메일 형식, 이름 길이/형식',
      '✅ 응답에 password_hash 절대 미포함',
      '✅ SQL 파라미터화 쿼리',
    ],
    frontendChecklist: [
      '✅ 비밀번호 강도 표시기 (UI)',
      '✅ 비밀번호 확인 필드 일치 검증',
      '✅ 폼 제출 후 비밀번호 필드 초기화',
      '✅ HTTPS 전용 (비밀번호 평문 전송 방지)',
    ],
    requiredMiddleware: [
      'express-rate-limit - 가입 속도 제한',
    ],
    commonMistakes: [
      '❌ SHA256(password) → bcrypt/scrypt/Argon2 사용 필수',
      '❌ if (existingUser) return "이미 가입됨" → 계정 열거 공격',
      '❌ password 평문 DB 저장 → 반드시 해싱',
      '❌ Rate Limiting 미적용 → 봇 대량 가입',
    ],
    requiredPackages: [
      { name: 'bcrypt', purpose: '비밀번호 해싱' },
      { name: 'zod', purpose: '입력값 검증' },
      { name: 'express-rate-limit', purpose: '속도 제한' },
    ],
  },

  {
    keywords: ['로그인', 'login', 'signin', 'sign-in', '인증', 'auth', '로그인 페이지', '로그인 폼', 'login page'],
    featureName: 'Login / Authentication',
    featureNameKo: '로그인 / 인증',
    threats: [
      '무차별 대입: 비밀번호 반복 시도',
      '자격증명 스터핑: 유출된 비밀번호 목록 대입',
      '세션 하이재킹: 쿠키 탈취',
      '타이밍 공격: 사용자 존재 여부 추론',
      'JWT 조작: none 알고리즘 공격',
    ],
    backendChecklist: [
      '✅ bcrypt.compare()로 비밀번호 검증',
      '✅ Rate Limiting: 15분당 5회 로그인 시도 제한',
      '✅ 타이밍 공격 방지: 사용자 미존재 시에도 bcrypt.compare 실행',
      '✅ 에러 메시지: "이메일 또는 비밀번호가 틀렸습니다" (통합 메시지)',
      '✅ JWT 발급 시 알고리즘 명시 (HS256)',
      '✅ JWT 만료 시간 설정 (예: 1시간)',
      '✅ 쿠키: HttpOnly + Secure + SameSite=Strict',
      '✅ 로그인 성공/실패 로깅 (감사 추적)',
    ],
    frontendChecklist: [
      '✅ 비밀번호 입력 필드 type="password"',
      '✅ 폼 제출 후 비밀번호 메모리에서 제거',
      '✅ 자동완성 속성 적절히 설정',
      '✅ HTTPS 전용',
    ],
    requiredMiddleware: [
      'express-rate-limit - 로그인 속도 제한',
      'cookie-parser - 쿠키 파싱',
    ],
    commonMistakes: [
      '❌ if (!user) return "사용자가 없습니다" → 계정 열거',
      '❌ jwt.sign(payload, secret) → 알고리즘 미명시 (none 공격)',
      '❌ res.cookie("token", token) → HttpOnly/Secure 플래그 누락',
      '❌ Rate Limiting 없음 → 무차별 대입 공격',
    ],
    requiredPackages: [
      { name: 'bcrypt', purpose: '비밀번호 검증' },
      { name: 'jsonwebtoken', purpose: 'JWT 발급/검증' },
      { name: 'express-rate-limit', purpose: '속도 제한' },
    ],
  },

  {
    keywords: ['댓글', 'comment', 'reply', '답글', '리플', '덧글', '댓글 페이지'],
    featureName: 'Comment System',
    featureNameKo: '댓글 시스템',
    threats: [
      'Stored XSS: 댓글에 스크립트 삽입',
      'IDOR: 타인 댓글 삭제/수정',
      'Spam/Flood: 대량 댓글 작성',
      'SQL Injection: 댓글 내용/검색으로 DB 공격',
    ],
    backendChecklist: [
      '✅ 댓글 내용 HTML 이스케이프 (< → &lt;, > → &gt;)',
      '✅ 입력 검증: 최대 2000자, 공백만 불허',
      '✅ 삭제/수정 시 작성자 본인 확인',
      '✅ 부모 댓글/게시글 존재 여부 확인 (참조 무결성)',
      '✅ Rate Limiting: 분당 댓글 작성 횟수 제한',
      '✅ SQL 파라미터화 쿼리',
    ],
    frontendChecklist: [
      '✅ 댓글 표시 시 textContent 사용',
      '✅ XSS 방지 출력 인코딩',
    ],
    requiredMiddleware: ['authenticate', 'express-rate-limit'],
    commonMistakes: [
      '❌ innerHTML = comment.content → Stored XSS',
      '❌ DELETE /comments/:id 에서 작성자 확인 없음 → IDOR',
      '❌ 댓글 길이 제한 없음 → DB 과부하',
    ],
    requiredPackages: [
      { name: 'zod', purpose: '입력값 검증' },
      { name: 'express-rate-limit', purpose: '스팸 방지' },
    ],
  },

  {
    keywords: ['파일', 'upload', '업로드', '이미지', 'image', '첨부', '다운로드', 'download', '업로드 페이지', '파일 업로드 페이지'],
    featureName: 'File Upload / Download',
    featureNameKo: '파일 업로드 / 다운로드',
    threats: [
      '악성 파일 업로드: .exe, .php, .jsp 실행 파일 업로드',
      'Path Traversal: ../../etc/passwd 경로로 시스템 파일 접근',
      '파일 크기 DoS: 초대형 파일로 서버 디스크 가득 채우기',
      'MIME 위장: image/jpeg로 위장한 .php 파일',
      '다운로드 시 IDOR: 타인 파일 다운로드',
    ],
    backendChecklist: [
      '✅ MIME 타입 + 확장자 이중 검증',
      '✅ 파일 크기 제한 (예: 10MB)',
      '✅ 업로드 파일 개수 제한',
      '✅ 원본 파일명 비사용 → crypto.randomBytes() 랜덤 파일명',
      '✅ 업로드 디렉토리 경로 이탈 검사 (Path Traversal 방지)',
      '✅ 업로드 디렉토리에서 스크립트 실행 비활성화 (nginx/apache 설정)',
      '✅ 다운로드 시 파일 소유자 확인',
      '✅ Content-Disposition: attachment 헤더 설정',
    ],
    frontendChecklist: [
      '✅ accept 속성으로 허용 파일 타입 제한',
      '✅ 파일 크기 클라이언트 사전 검증',
      '✅ 업로드 진행률 표시',
    ],
    requiredMiddleware: ['authenticate', 'multer'],
    commonMistakes: [
      '❌ 원본 파일명 그대로 저장 → Path Traversal + 파일 덮어쓰기',
      '❌ MIME 타입만 검증 → 확장자 위장 공격',
      '❌ 업로드 디렉토리를 웹 루트 안에 설정 → 업로드 파일 직접 실행',
      '❌ 파일 크기 제한 없음 → 디스크 가득 채우기 DoS',
    ],
    requiredPackages: [
      { name: 'multer', purpose: '파일 업로드 처리' },
    ],
  },

  {
    keywords: ['검색', 'search', '찾기', 'find', '조회', '필터', 'filter', '검색 페이지'],
    featureName: 'Search / Filter',
    featureNameKo: '검색 / 필터링',
    threats: [
      'SQL Injection: 검색어로 SQL 공격',
      'LIKE Injection: %, _ 와일드카드로 전체 데이터 조회',
      'ORDER BY Injection: 정렬 파라미터로 DB 구조 유출',
      'DoS: LIMIT 없는 검색으로 대량 데이터 반환',
      'ReDoS: 정규표현식 서비스 거부',
    ],
    backendChecklist: [
      '✅ 검색어 SQL 파라미터화',
      '✅ LIKE 와일드카드(%, _) 이스케이프',
      '✅ ORDER BY 컬럼 화이트리스트',
      '✅ 페이지네이션 LIMIT 최대값 제한 (예: 50)',
      '✅ 검색어 길이 제한 (예: 100자)',
      '✅ 필요한 컬럼만 SELECT (최소 정보 원칙)',
    ],
    frontendChecklist: [
      '✅ 검색 결과를 textContent로 렌더링 (XSS 방지)',
      '✅ 검색 디바운싱 (서버 부하 감소)',
    ],
    requiredMiddleware: ['express-rate-limit'],
    commonMistakes: [
      '❌ WHERE title LIKE \'%${q}%\' → SQL Injection',
      '❌ ORDER BY ${sort} → ORDER BY Injection',
      '❌ LIMIT ${limit} 에서 limit 검증 없음 → LIMIT 999999999',
    ],
    requiredPackages: [
      { name: 'zod', purpose: '검색 파라미터 검증' },
    ],
  },

  {
    keywords: ['api', 'rest', 'endpoint', 'route', '라우트', 'crud'],
    featureName: 'REST API Endpoint',
    featureNameKo: 'REST API 엔드포인트',
    threats: [
      '인증 우회: 인증 미들웨어 누락',
      '과도한 데이터 노출: 불필요한 필드 응답',
      'Mass Assignment: 요청 body에서 role, isAdmin 등 변경',
      'Rate Limiting 부재: API 남용',
      'CORS 미설정: 모든 도메인에서 접근 가능',
    ],
    backendChecklist: [
      '✅ 모든 엔드포인트에 인증 미들웨어 적용 (공개 API 제외)',
      '✅ 요청 body에서 허용된 필드만 추출 (Mass Assignment 방지)',
      '✅ 응답에서 필요한 필드만 포함 (password_hash, internal_id 등 제외)',
      '✅ Rate Limiting 적용',
      '✅ CORS를 특정 도메인만 허용',
      '✅ helmet으로 보안 헤더 설정',
      '✅ 입력 검증 스키마 적용',
      '✅ HTTP 상태 코드 적절히 사용 (401/403/404/400)',
    ],
    frontendChecklist: [
      '✅ API 키를 프론트엔드 코드에 하드코딩하지 않기',
      '✅ 에러 처리 및 사용자 친화적 메시지',
    ],
    requiredMiddleware: [
      'helmet - 보안 헤더',
      'cors - CORS 정책',
      'express-rate-limit - 속도 제한',
      'authenticate - 인증',
    ],
    commonMistakes: [
      '❌ app.use(cors()) → 모든 도메인 허용',
      '❌ res.json(user) → password_hash 등 전체 필드 노출',
      '❌ const { ...fields } = req.body → Mass Assignment',
      '❌ 인증 미들웨어 누락',
    ],
    requiredPackages: [
      { name: 'helmet', purpose: '보안 헤더' },
      { name: 'cors', purpose: 'CORS 정책' },
      { name: 'express-rate-limit', purpose: '속도 제한' },
      { name: 'zod', purpose: '입력 검증' },
    ],
  },
];

export function handleSecureDevelop(input: SecureDevelopInput) {
  const searchText = input.feature.toLowerCase();

  let bestGuide: FeatureSecurityGuide | undefined;
  let bestScore = 0;

  for (const guide of FEATURE_GUIDES) {
    let score = 0;
    for (const kw of guide.keywords) {
      if (searchText.includes(kw.toLowerCase())) score += 2;
    }
    if (score > bestScore) {
      bestScore = score;
      bestGuide = guide;
    }
  }

  const lines: string[] = [];

  lines.push(`# 🛡️ 시큐어 개발 가이드: ${input.feature}`);
  lines.push('');

  if (bestGuide && bestScore > 0) {
    lines.push(`## 기능: ${bestGuide.featureNameKo}`);
    lines.push('');

    lines.push('## ⚠️ 이 기능의 주요 보안 위협');
    lines.push('');
    for (const t of bestGuide.threats) {
      lines.push(`- 🔴 ${t}`);
    }
    lines.push('');

    lines.push('## ✅ 백엔드 보안 체크리스트 (필수 적용)');
    lines.push('');
    for (const c of bestGuide.backendChecklist) {
      lines.push(`- ${c}`);
    }
    lines.push('');

    // "페이지", "폼", "html" 키워드 포함 여부 → 프론트엔드 가이드 자동 활성화
    const isFrontendRequest = /페이지|폼|form|page|html|프론트|front/i.test(input.feature);
    const showFrontend = input.includes_frontend || isFrontendRequest;

    if (showFrontend && bestGuide.frontendChecklist.length > 0) {
      lines.push('## ✅ 프론트엔드 보안 체크리스트');
      lines.push('');
      for (const c of bestGuide.frontendChecklist) {
        lines.push(`- ${c}`);
      }
      lines.push('');
      lines.push('### 🌐 HTML 페이지 공통 보안 (필수)');
      lines.push('');
      lines.push('- ✅ `<meta http-equiv="Content-Security-Policy">` CSP 헤더 설정');
      lines.push('- ✅ `<meta http-equiv="X-Frame-Options" content="DENY">` 클릭재킹 방지');
      lines.push('- ✅ `<meta http-equiv="X-Content-Type-Options" content="nosniff">`');
      lines.push('- ✅ 동적 텍스트 삽입 시 `textContent` 사용 (`innerHTML` 금지)');
      lines.push('- ✅ `<form>` 에 CSRF 토큰 hidden field 포함');
      lines.push('- ✅ `<input type="password">` + `autocomplete="current-password"` 또는 `"new-password"`');
      lines.push('- ✅ 비밀번호 입력 필드는 제출 후 `.value = ""` 로 초기화');
      lines.push('- ✅ API 호출 시 `credentials: "same-origin"` 설정');
      lines.push('- ✅ 리다이렉트 URL이 같은 origin인지 확인 (Open Redirect 방지)');
      lines.push('- ✅ 파일 `<input>` 에 `accept` 속성으로 허용 타입 제한');
      lines.push('- ✅ 에러 메시지에 서버 내부 정보 미표시');
      lines.push('');
    }

    lines.push('## 📦 필수 보안 패키지');
    lines.push('');
    for (const p of bestGuide.requiredPackages) {
      lines.push(`- \`${p.name}\` - ${p.purpose}`);
    }
    lines.push('');

    lines.push('## 🔧 필수 미들웨어');
    lines.push('');
    for (const m of bestGuide.requiredMiddleware) {
      lines.push(`- ${m}`);
    }
    lines.push('');

    lines.push('## ❌ 흔한 보안 실수 (절대 하지 마세요)');
    lines.push('');
    for (const m of bestGuide.commonMistakes) {
      lines.push(`- ${m}`);
    }
    if (showFrontend) {
      lines.push('- ❌ `innerHTML = userInput` → Stored XSS 취약점');
      lines.push('- ❌ `document.write(data)` → DOM 기반 XSS');
      lines.push('- ❌ `eval(userInput)` → 원격 코드 실행');
      lines.push('- ❌ `location.href = req.query.redirect` → Open Redirect');
      lines.push('- ❌ `localStorage.setItem("token", jwt)` → XSS로 토큰 탈취 (HttpOnly 쿠키 사용)');
    }
    lines.push('');

    if (bestGuide.dbSchema) {
      lines.push('## 📊 권장 DB 스키마');
      lines.push('');
      lines.push('```sql');
      lines.push(bestGuide.dbSchema);
      lines.push('```');
      lines.push('');
    }

    lines.push('---');
    lines.push('> ⚠️ 위 체크리스트를 모두 적용하여 코드를 작성하세요.');
    if (showFrontend) {
      lines.push('> 💡 `generate_secure_code` 도구를 language="html"로 호출하면 보안이 적용된 완전한 HTML 페이지 템플릿을 받을 수 있습니다.');
    } else {
      lines.push('> 💡 `generate_secure_code` 도구에서 이 기능의 시큐어 코드 템플릿을 확인할 수 있습니다.');
    }
  } else {
    lines.push('## 일반 웹 기능 보안 체크리스트');
    lines.push('');
    lines.push('요청하신 기능에 특화된 가이드가 없어 범용 보안 체크리스트를 제공합니다.');
    lines.push('');
    lines.push('### 백엔드');
    lines.push('- ✅ 모든 외부 입력을 검증 (zod/joi)');
    lines.push('- ✅ SQL 쿼리 파라미터화 ($1, $2)');
    lines.push('- ✅ 인증 미들웨어 적용');
    lines.push('- ✅ 리소스 접근 시 소유자 확인 (IDOR 방지)');
    lines.push('- ✅ 에러 상세 미노출');
    lines.push('- ✅ Rate Limiting');
    lines.push('- ✅ helmet 보안 헤더');
    lines.push('- ✅ CORS 제한');
    lines.push('');
    lines.push('### 프론트엔드');
    lines.push('- ✅ 사용자 입력을 DOM에 삽입 시 textContent 사용');
    lines.push('- ✅ CSRF 토큰 포함');
    lines.push('- ✅ HTTPS 전용');
    lines.push('');
    lines.push('### 절대 하지 마세요');
    lines.push('- ❌ SQL 문자열 결합');
    lines.push('- ❌ innerHTML로 사용자 입력 삽입');
    lines.push('- ❌ 비밀번호 평문 저장');
    lines.push('- ❌ 시크릿 하드코딩');
    lines.push('- ❌ err.stack 클라이언트 전송');
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
  };
}
