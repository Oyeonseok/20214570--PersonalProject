export interface SecurityBlueprint {
  feature: string;
  featureKo: string;
  threats: string[];
  requiredSecurity: SecurityRequirement[];
  architecture: string;
}

export interface SecurityRequirement {
  category: string;
  technique: string;
  priority: 'critical' | 'high' | 'medium';
  implementation: string;
}

const BLUEPRINTS: SecurityBlueprint[] = [
  {
    feature: 'login',
    featureKo: '로그인',
    threats: ['Brute Force', 'Credential Stuffing', 'Session Hijacking', 'Timing Attack'],
    requiredSecurity: [
      { category: '비밀번호', technique: 'bcrypt(cost>=12)로 해싱, 평문 저장 금지', priority: 'critical', implementation: "import bcrypt from 'bcrypt'; await bcrypt.hash(password, 12);" },
      { category: '속도 제한', technique: 'IP+계정별 로그인 시도 제한 (5회/15분)', priority: 'critical', implementation: "rateLimit({ windowMs: 15*60*1000, max: 5, keyGenerator: (req) => req.body.email + req.ip })" },
      { category: '세션', technique: '로그인 성공 시 세션 ID 재생성, httpOnly+secure+sameSite 쿠키', priority: 'critical', implementation: "req.session.regenerate(); res.cookie('sid', id, { httpOnly: true, secure: true, sameSite: 'strict' })" },
      { category: '타이밍', technique: '존재하지 않는 계정도 동일 시간 소요 (bcrypt.compare 항상 실행)', priority: 'high', implementation: "const user = await findUser(email); const hash = user?.hash ?? '$2b$12$dummy...'; await bcrypt.compare(password, hash);" },
      { category: '에러 메시지', technique: '"이메일 또는 비밀번호가 올바르지 않습니다" (구체적 정보 노출 금지)', priority: 'high', implementation: "res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다' });" },
      { category: 'JWT', technique: 'algorithm pinning(HS256), 만료시간 설정, refresh token 분리', priority: 'high', implementation: "jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: '15m' })" },
      { category: '로깅', technique: '로그인 실패/성공 로깅 (비밀번호 제외)', priority: 'medium', implementation: "logger.info({ event: 'login', email, success: true, ip: req.ip });" },
    ],
    architecture: `// 최적 로그인 아키텍처
POST /api/auth/login
├── Rate Limiter (IP+email 기반)
├── Input Validation (zod: email, password)
├── User Lookup (parameterized query)
├── Password Verify (bcrypt.compare, timing-safe)
├── Session/JWT Generation (algorithm pinning)
├── Audit Log (성공/실패 기록)
└── Response (토큰 + httpOnly 쿠키)`,
  },
  {
    feature: 'registration',
    featureKo: '회원가입',
    threats: ['Mass Registration Bot', 'Weak Password', 'Email Enumeration', 'SQL Injection'],
    requiredSecurity: [
      { category: '입력 검증', technique: 'zod로 email/password/name 스키마 검증', priority: 'critical', implementation: "z.object({ email: z.string().email(), password: z.string().min(8).regex(/[A-Z]/).regex(/[0-9]/) })" },
      { category: '비밀번호 정책', technique: '최소 8자, 대소문자+숫자+특수문자 포함, 유출 DB 대조', priority: 'critical', implementation: "password.length >= 8 && /[A-Z]/.test(p) && /[0-9]/.test(p) && /[!@#$%]/.test(p)" },
      { category: 'SQL 인젝션', technique: '파라미터화 쿼리 사용, 문자열 결합 금지', priority: 'critical', implementation: "db.query('INSERT INTO users (email, hash) VALUES ($1, $2)', [email, hash])" },
      { category: '이메일 열거', technique: '이미 존재하는 이메일도 "확인 메일 발송" 동일 응답', priority: 'high', implementation: "res.json({ message: '확인 이메일을 발송했습니다' }); // 존재 여부 무관" },
      { category: 'CAPTCHA', technique: 'reCAPTCHA 또는 hCaptcha로 봇 방지', priority: 'high', implementation: "await verifyRecaptcha(req.body.captchaToken);" },
      { category: '속도 제한', technique: 'IP별 가입 시도 제한', priority: 'medium', implementation: "rateLimit({ windowMs: 60*60*1000, max: 3 })" },
    ],
    architecture: `// 최적 회원가입 아키텍처
POST /api/auth/register
├── Rate Limiter (IP 기반)
├── CAPTCHA Verification
├── Input Validation (zod: email, password policy, name)
├── Duplicate Check (timing-safe response)
├── Password Hashing (bcrypt, cost 12)
├── DB Insert (parameterized query)
├── Email Verification Token 발송
└── Response (일관된 메시지)`,
  },
  {
    feature: 'board',
    featureKo: '게시판',
    threats: ['XSS (Stored/Reflected)', 'SQL Injection', 'IDOR', 'CSRF', 'Path Traversal'],
    requiredSecurity: [
      { category: 'XSS 방지', technique: '출력 시 HTML 이스케이프, DOMPurify로 sanitize', priority: 'critical', implementation: "import DOMPurify from 'dompurify'; const safe = DOMPurify.sanitize(userHtml);" },
      { category: 'SQL 인젝션', technique: '모든 쿼리 파라미터화, ORM 사용 권장', priority: 'critical', implementation: "db.query('SELECT * FROM posts WHERE id = $1', [postId])" },
      { category: 'IDOR 방지', technique: '게시글 수정/삭제 시 작성자 본인 확인', priority: 'critical', implementation: "WHERE id = $1 AND author_id = $2 -- 소유권 확인 필수" },
      { category: 'CSRF', technique: 'Double Submit Cookie 또는 Synchronizer Token', priority: 'high', implementation: "const token = crypto.randomBytes(32).toString('hex'); // CSRF 토큰 생성" },
      { category: '페이지네이션', technique: 'LIMIT/OFFSET에 상한값 설정, 음수 방지', priority: 'medium', implementation: "const limit = Math.min(Math.max(1, input.limit), 100);" },
      { category: 'Rate Limiting', technique: '게시글 작성 속도 제한', priority: 'medium', implementation: "rateLimit({ windowMs: 60000, max: 10 }) // 분당 10회" },
    ],
    architecture: `// 최적 게시판 아키텍처
GET  /api/posts       ← 목록 (페이지네이션, 검색: LIKE 와일드카드 이스케이프)
GET  /api/posts/:id   ← 상세 (parameterized query)
POST /api/posts       ← 작성 (auth + CSRF + XSS sanitize + rate limit)
PUT  /api/posts/:id   ← 수정 (auth + IDOR check + CSRF + sanitize)
DELETE /api/posts/:id ← 삭제 (auth + IDOR check + CSRF)`,
  },
  {
    feature: 'file-upload',
    featureKo: '파일 업로드',
    threats: ['Malicious File Upload', 'Path Traversal', 'DoS (Large File)', 'SSRF'],
    requiredSecurity: [
      { category: '파일 타입', technique: 'MIME + 매직바이트 검증 (확장자만 믿지 않기)', priority: 'critical', implementation: "const ALLOWED = ['image/jpeg','image/png','application/pdf']; if (!ALLOWED.includes(file.mimetype)) reject();" },
      { category: '파일명', technique: 'crypto.randomUUID()로 랜덤 파일명, 원본 파일명 저장만', priority: 'critical', implementation: "const filename = crypto.randomUUID() + path.extname(file.originalname);" },
      { category: '크기 제한', technique: '파일 크기 상한 설정 (예: 5MB)', priority: 'critical', implementation: "multer({ limits: { fileSize: 5 * 1024 * 1024 } })" },
      { category: '경로 검증', technique: 'path.resolve() + 기본 디렉토리 밖 접근 차단', priority: 'critical', implementation: "const resolved = path.resolve(uploadDir, filename); if (!resolved.startsWith(uploadDir)) reject();" },
      { category: '저장 위치', technique: '웹 루트 밖에 저장, 직접 URL 접근 차단', priority: 'high', implementation: "// uploads/ 디렉토리는 static 서빙하지 않고 별도 API로 제공" },
      { category: '바이러스 검사', technique: 'ClamAV 등으로 업로드 파일 스캔', priority: 'medium', implementation: "await clamav.scanStream(fileStream);" },
    ],
    architecture: `// 최적 파일 업로드 아키텍처
POST /api/upload
├── Auth Middleware (로그인 필수)
├── Rate Limiter
├── multer (크기 제한 + MIME 필터)
├── 매직바이트 검증
├── 랜덤 파일명 생성
├── Path Traversal 검증
├── 저장 (웹 루트 외부)
└── DB에 메타데이터 저장

GET /api/files/:id ← 다운로드 (소유권 확인 + Content-Disposition)`,
  },
  {
    feature: 'search',
    featureKo: '검색',
    threats: ['SQL Injection', 'XSS (Reflected)', 'DoS (Heavy Query)', 'Information Disclosure'],
    requiredSecurity: [
      { category: 'SQL 인젝션', technique: 'LIKE 와일드카드 이스케이프 + 파라미터화', priority: 'critical', implementation: "const escaped = search.replace(/[%_\\\\]/g, '\\\\$&'); db.query('WHERE title ILIKE $1', [`%${escaped}%`])" },
      { category: 'XSS', technique: '검색어 출력 시 HTML 이스케이프', priority: 'critical', implementation: "검색 결과에 사용자 입력을 표시할 때 반드시 이스케이프" },
      { category: 'DoS 방지', technique: '검색 결과 수 제한, 쿼리 타임아웃', priority: 'high', implementation: "LIMIT 100; SET statement_timeout = '5s';" },
      { category: '속도 제한', technique: '검색 API rate limiting', priority: 'medium', implementation: "rateLimit({ windowMs: 60000, max: 30 })" },
    ],
    architecture: `// 최적 검색 아키텍처
GET /api/search?q=keyword&page=1&limit=20
├── Rate Limiter
├── Input Validation (검색어 길이 제한)
├── LIKE 와일드카드 이스케이프
├── Parameterized Query + LIMIT
├── 결과 HTML 이스케이프
└── 페이지네이션 (offset 상한 설정)`,
  },
  {
    feature: 'api',
    featureKo: 'REST API',
    threats: ['Injection', 'Broken Auth', 'Mass Assignment', 'Rate Limit Bypass', 'SSRF'],
    requiredSecurity: [
      { category: '인증', technique: 'JWT Bearer 토큰 + algorithm pinning', priority: 'critical', implementation: "jwt.verify(token, secret, { algorithms: ['HS256'] })" },
      { category: '입력 검증', technique: '모든 엔드포인트에 zod 스키마 적용', priority: 'critical', implementation: "const schema = z.object({...}).strict(); // strict()로 추가 필드 차단" },
      { category: 'Mass Assignment', technique: '.strict() 또는 .pick()으로 허용 필드만 추출', priority: 'high', implementation: "const allowed = schema.pick({ name: true, email: true }).parse(req.body);" },
      { category: '보안 헤더', technique: 'helmet() 적용', priority: 'high', implementation: "app.use(helmet());" },
      { category: 'CORS', technique: '허용 origin 명시 (와일드카드 금지)', priority: 'high', implementation: "cors({ origin: ['https://myapp.com'], credentials: true })" },
      { category: 'Rate Limiting', technique: '엔드포인트별 차등 제한', priority: 'high', implementation: "app.use('/api/auth', rateLimit({ max: 10 })); app.use('/api', rateLimit({ max: 100 }));" },
      { category: '에러 처리', technique: '스택 트레이스 노출 금지, 일관된 에러 포맷', priority: 'medium', implementation: "res.status(500).json({ error: 'Internal server error', requestId });" },
    ],
    architecture: `// 최적 API 아키텍처
Express App
├── helmet() (보안 헤더)
├── cors() (명시적 origin)
├── express.json({ limit: '1mb' })
├── Global Rate Limiter
├── Routes
│   ├── /api/auth/* (인증 라우트 - 강화된 rate limit)
│   ├── /api/* (인증 필요 라우트 - authMiddleware)
│   └── /health (공개)
├── 404 Handler
└── Error Handler (스택 숨김)`,
  },
  {
    feature: 'comment',
    featureKo: '댓글',
    threats: ['Stored XSS', 'SQL Injection', 'Spam', 'CSRF', 'IDOR'],
    requiredSecurity: [
      { category: 'XSS', technique: '댓글 내용 HTML 이스케이프 또는 DOMPurify', priority: 'critical', implementation: "const safeContent = DOMPurify.sanitize(comment, { ALLOWED_TAGS: [] });" },
      { category: 'SQL 인젝션', technique: '파라미터화 쿼리', priority: 'critical', implementation: "db.query('INSERT INTO comments (post_id, user_id, content) VALUES ($1,$2,$3)', [postId, userId, content])" },
      { category: 'IDOR', technique: '삭제/수정 시 작성자 확인', priority: 'high', implementation: "WHERE id = $1 AND user_id = $2" },
      { category: '스팸 방지', technique: 'Rate limiting + 최소 시간 간격', priority: 'high', implementation: "rateLimit({ windowMs: 60000, max: 5 }) // 분당 5개" },
      { category: '길이 제한', technique: '댓글 최대 길이 설정', priority: 'medium', implementation: "z.string().max(2000)" },
    ],
    architecture: `// 최적 댓글 아키텍처
POST /api/posts/:postId/comments
├── Auth + Rate Limit
├── Input Validation (content: max 2000자)
├── XSS Sanitize
├── Parameterized INSERT
└── Response

DELETE /api/comments/:id
├── Auth + IDOR Check (작성자 본인만)
└── Soft Delete 권장`,
  },
];

export function getSecurityBlueprint(feature?: string): string {
  const lines: string[] = [];

  if (feature) {
    const bp = BLUEPRINTS.find((b) =>
      b.feature === feature.toLowerCase() ||
      b.featureKo === feature ||
      feature.toLowerCase().includes(b.feature),
    );
    if (bp) {
      lines.push(...formatBlueprint(bp));
    } else {
      lines.push(`"${feature}"에 대한 블루프린트가 없습니다. 사용 가능: ${BLUEPRINTS.map((b) => b.featureKo).join(', ')}`);
    }
  } else {
    lines.push('# 보안 설계 블루프린트');
    lines.push('');
    lines.push('기능별 최적의 보안 설계를 제공합니다. Claude는 이 블루프린트를 참고하여 코드를 작성하세요.');
    lines.push('');
    for (const bp of BLUEPRINTS) {
      lines.push(...formatBlueprint(bp));
      lines.push('---');
      lines.push('');
    }
  }

  return lines.join('\n');
}

function formatBlueprint(bp: SecurityBlueprint): string[] {
  const lines: string[] = [];
  lines.push(`## ${bp.featureKo} (${bp.feature}) 보안 블루프린트`);
  lines.push('');
  lines.push(`**위협:** ${bp.threats.join(', ')}`);
  lines.push('');
  lines.push('### 필수 보안 요구사항');
  lines.push('');
  lines.push('| 우선순위 | 카테고리 | 기법 |');
  lines.push('|----------|----------|------|');
  for (const req of bp.requiredSecurity) {
    const badge = req.priority === 'critical' ? '🔴' : req.priority === 'high' ? '🟠' : '🟡';
    lines.push(`| ${badge} ${req.priority} | ${req.category} | ${req.technique} |`);
  }
  lines.push('');
  lines.push('### 구현 코드');
  lines.push('');
  for (const req of bp.requiredSecurity) {
    lines.push(`**${req.category}:**`);
    lines.push('```typescript');
    lines.push(req.implementation);
    lines.push('```');
    lines.push('');
  }
  lines.push('### 아키텍처');
  lines.push('```');
  lines.push(bp.architecture);
  lines.push('```');
  lines.push('');
  return lines;
}

export function getAvailableFeatures(): string[] {
  return BLUEPRINTS.map((b) => b.feature);
}
