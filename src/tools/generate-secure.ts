import { z } from 'zod';

export const generateSecureSchema = z.object({
  vulnerable_code: z.string().optional().describe('취약한 원본 코드 (변환 모드)'),
  task: z.string().optional().describe("구현할 웹 기능 설명 (예: '로그인 페이지', '게시글 작성 페이지', '회원가입 폼', '댓글', '파일 업로드', '검색 페이지')"),
  language: z.enum(['javascript', 'typescript', 'python', 'java', 'html']).describe("프로그래밍 언어. 프론트엔드 HTML 페이지를 만들 때는 'html'을 사용하세요."),
  framework: z.string().optional().describe('대상 프레임워크 (예: express, react, nextjs, vanilla, fastapi, spring)'),
});

export type GenerateSecureInput = z.infer<typeof generateSecureSchema>;

interface SecureTemplate {
  keywords: string[];
  language: string[];
  framework?: string[];
  code: string;
  explanationKo: string;
  securityChecklist: string[];
  appliedDefenses: string[];
}

const SECURE_TEMPLATES: SecureTemplate[] = [
  // ── 게시글 작성 (Board / Post) ──
  {
    keywords: ['게시글', '게시판', '글쓰기', '글 작성', 'post', 'board', 'article', 'write', 'create post', 'blog'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';
import { authenticate } from './middleware/auth';

const router = Router();

// ── 입력 검증 스키마 ──
const createPostSchema = z.object({
  title: z
    .string()
    .min(1, '제목을 입력하세요')
    .max(200, '제목은 200자 이하')
    .transform((val) => val.trim()),
  content: z
    .string()
    .min(1, '내용을 입력하세요')
    .max(50000, '내용은 50000자 이하'),
  category: z
    .string()
    .regex(/^[a-zA-Z0-9_-]+$/, '유효하지 않은 카테고리')
    .optional(),
});

const listPostsSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().max(100).optional(),
});

// ── 게시글 작성 ──
router.post('/posts', authenticate, async (req: Request, res: Response) => {
  try {
    const { title, content, category } = createPostSchema.parse(req.body);
    const userId = req.user!.userId;

    // XSS 방지: HTML 콘텐츠를 허용하는 경우 DOMPurify로 새니타이즈
    const sanitizedContent = DOMPurify.sanitize(content, {
      ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'u', 'a', 'ul', 'ol', 'li', 'h2', 'h3', 'blockquote', 'code', 'pre'],
      ALLOWED_ATTR: ['href', 'target', 'rel'],
    });

    // SQL 인젝션 방지: 파라미터화 쿼리
    const result = await db.query(
      \`INSERT INTO posts (title, content, category, author_id, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id, title, created_at\`,
      [title, sanitizedContent, category ?? 'general', userId]
    );

    res.status(201).json({
      message: '게시글이 작성되었습니다',
      post: result.rows[0],
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({
        error: '입력값이 올바르지 않습니다',
        details: err.errors.map((e) => ({ field: e.path.join('.'), message: e.message })),
      });
    }
    console.error('Post creation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── 게시글 목록 조회 ──
router.get('/posts', async (req: Request, res: Response) => {
  try {
    const { page, limit, search } = listPostsSchema.parse(req.query);
    const offset = (page - 1) * limit;

    let query: string;
    let params: unknown[];

    if (search) {
      // 검색어 SQL 인젝션 방지 + LIKE 와일드카드 이스케이프
      const escapedSearch = search.replace(/[%_\\\\]/g, '\\\\$&');
      query = \`SELECT p.id, p.title, p.category, p.created_at, u.name as author
               FROM posts p JOIN users u ON p.author_id = u.id
               WHERE p.title ILIKE $1 OR p.content ILIKE $1
               ORDER BY p.created_at DESC LIMIT $2 OFFSET $3\`;
      params = [\`%\${escapedSearch}%\`, limit, offset];
    } else {
      query = \`SELECT p.id, p.title, p.category, p.created_at, u.name as author
               FROM posts p JOIN users u ON p.author_id = u.id
               ORDER BY p.created_at DESC LIMIT $1 OFFSET $2\`;
      params = [limit, offset];
    }

    const result = await db.query(query, params);
    // 응답에 민감정보 미포함 (author_id, email 등 제외)
    res.json({ posts: result.rows, page, limit });
  } catch (err) {
    console.error('Post list error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── 게시글 상세 조회 ──
router.get('/posts/:id', async (req: Request, res: Response) => {
  const postId = parseInt(req.params.id, 10);
  if (isNaN(postId) || postId < 1) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }

  const result = await db.query(
    \`SELECT p.id, p.title, p.content, p.category, p.created_at, p.updated_at,
            u.name as author, u.id as author_id
     FROM posts p JOIN users u ON p.author_id = u.id
     WHERE p.id = $1\`,
    [postId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Post not found' });
  }

  res.json({ post: result.rows[0] });
});

// ── 게시글 수정 (본인만) ──
router.put('/posts/:id', authenticate, async (req: Request, res: Response) => {
  const postId = parseInt(req.params.id, 10);
  if (isNaN(postId) || postId < 1) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }

  const { title, content } = createPostSchema.parse(req.body);
  const userId = req.user!.userId;

  // 권한 검증: 본인 글만 수정 가능 (IDOR 방지)
  const existing = await db.query('SELECT author_id FROM posts WHERE id = $1', [postId]);
  if (existing.rows.length === 0) {
    return res.status(404).json({ error: 'Post not found' });
  }
  if (existing.rows[0].author_id !== userId && req.user!.role !== 'admin') {
    return res.status(403).json({ error: 'Permission denied' });
  }

  const sanitizedContent = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'u', 'a', 'ul', 'ol', 'li', 'h2', 'h3', 'blockquote', 'code', 'pre'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
  });

  await db.query(
    'UPDATE posts SET title = $1, content = $2, updated_at = NOW() WHERE id = $3',
    [title, sanitizedContent, postId]
  );

  res.json({ message: '게시글이 수정되었습니다' });
});

// ── 게시글 삭제 (본인만) ──
router.delete('/posts/:id', authenticate, async (req: Request, res: Response) => {
  const postId = parseInt(req.params.id, 10);
  if (isNaN(postId) || postId < 1) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }

  const userId = req.user!.userId;

  const existing = await db.query('SELECT author_id FROM posts WHERE id = $1', [postId]);
  if (existing.rows.length === 0) {
    return res.status(404).json({ error: 'Post not found' });
  }
  if (existing.rows[0].author_id !== userId && req.user!.role !== 'admin') {
    return res.status(403).json({ error: 'Permission denied' });
  }

  await db.query('DELETE FROM posts WHERE id = $1', [postId]);
  res.json({ message: '게시글이 삭제되었습니다' });
});

export default router;`,
    explanationKo: 'XSS 방지(DOMPurify), SQL 인젝션 방지(파라미터 쿼리), 인증/인가(JWT + 본인확인), 입력검증(zod)이 모두 적용된 게시판 CRUD API',
    securityChecklist: [
      '[XSS] 게시글 내용을 DOMPurify로 새니타이즈하여 Stored XSS 차단',
      '[SQL Injection] 모든 쿼리를 파라미터화($1, $2)하여 SQL 인젝션 원천 차단',
      '[인증] authenticate 미들웨어로 로그인 확인 필수',
      '[인가/IDOR] 게시글 수정/삭제 시 본인 글인지 확인하여 IDOR 공격 차단',
      '[입력 검증] zod 스키마로 제목 200자, 내용 50000자, 카테고리 형식 검증',
      '[검색 인젝션] LIKE 와일드카드(%, _) 이스케이프 처리',
      '[정보 노출] 응답에 author_id 외 민감정보(email 등) 미포함',
      '[에러 처리] 클라이언트에 Internal server error만 반환, 상세 에러는 서버 로그만',
      '[페이지네이션] LIMIT/OFFSET에 최대값 제한(100)으로 DoS 방지',
    ],
    appliedDefenses: [
      'A01-Broken Access Control: 본인 글만 수정/삭제 (IDOR 방지)',
      'A03-Injection: 파라미터화 쿼리 + LIKE 이스케이프',
      'A03-XSS: DOMPurify HTML 새니타이즈',
      'A04-Insecure Design: 입력값 검증 스키마',
      'A05-Misconfiguration: 에러 상세 미노출',
      'A07-Auth Failures: JWT 인증 미들웨어 필수',
    ],
  },

  // ── 댓글 ──
  {
    keywords: ['댓글', 'comment', 'reply', '답글', '리플'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { authenticate } from './middleware/auth';

const router = Router();

const createCommentSchema = z.object({
  content: z
    .string()
    .min(1, '댓글을 입력하세요')
    .max(2000, '댓글은 2000자 이하')
    .transform((val) => val.trim()),
  parent_id: z.number().int().positive().optional(),
});

// ── 댓글 작성 ──
router.post('/posts/:postId/comments', authenticate, async (req: Request, res: Response) => {
  try {
    const postId = parseInt(req.params.postId, 10);
    if (isNaN(postId) || postId < 1) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const { content, parent_id } = createCommentSchema.parse(req.body);
    const userId = req.user!.userId;

    // 게시글 존재 여부 확인
    const post = await db.query('SELECT id FROM posts WHERE id = $1', [postId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // 부모 댓글 존재 여부 확인 (대댓글인 경우)
    if (parent_id) {
      const parent = await db.query(
        'SELECT id FROM comments WHERE id = $1 AND post_id = $2',
        [parent_id, postId]
      );
      if (parent.rows.length === 0) {
        return res.status(404).json({ error: 'Parent comment not found' });
      }
    }

    // XSS 방지: 댓글은 일반 텍스트로만 저장 (HTML 태그 제거)
    const safeContent = content.replace(/</g, '&lt;').replace(/>/g, '&gt;');

    const result = await db.query(
      \`INSERT INTO comments (post_id, author_id, content, parent_id, created_at)
       VALUES ($1, $2, $3, $4, NOW()) RETURNING id, created_at\`,
      [postId, userId, safeContent, parent_id ?? null]
    );

    res.status(201).json({ comment: result.rows[0] });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: '입력값이 올바르지 않습니다' });
    }
    console.error('Comment creation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── 댓글 삭제 (본인/관리자만) ──
router.delete('/comments/:id', authenticate, async (req: Request, res: Response) => {
  const commentId = parseInt(req.params.id, 10);
  if (isNaN(commentId) || commentId < 1) {
    return res.status(400).json({ error: 'Invalid comment ID' });
  }

  const existing = await db.query('SELECT author_id FROM comments WHERE id = $1', [commentId]);
  if (existing.rows.length === 0) {
    return res.status(404).json({ error: 'Comment not found' });
  }
  if (existing.rows[0].author_id !== req.user!.userId && req.user!.role !== 'admin') {
    return res.status(403).json({ error: 'Permission denied' });
  }

  await db.query('DELETE FROM comments WHERE id = $1', [commentId]);
  res.json({ message: '댓글이 삭제되었습니다' });
});

export default router;`,
    explanationKo: 'XSS 방지(HTML 이스케이프), SQL 인젝션 방지, 인증/인가, 대댓글 참조 무결성 검증이 적용된 댓글 API',
    securityChecklist: [
      '[XSS] HTML 태그를 이스케이프(&lt; &gt;)하여 Stored XSS 차단',
      '[SQL Injection] 파라미터화 쿼리로 인젝션 차단',
      '[인증] 로그인 사용자만 댓글 작성 가능',
      '[인가] 본인 댓글만 삭제 가능 (관리자 예외)',
      '[참조 무결성] 부모 댓글/게시글 존재 여부 확인',
      '[입력 검증] 2000자 제한 + trim 처리',
    ],
    appliedDefenses: [
      'A01-Broken Access Control: 본인 댓글만 삭제',
      'A03-Injection: 파라미터화 쿼리',
      'A03-XSS: HTML 엔티티 이스케이프',
    ],
  },

  // ── 회원가입 ──
  {
    keywords: ['회원가입', 'register', 'signup', 'sign-up', '가입', '계정 생성'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';

const router = Router();
const SALT_ROUNDS = 12;

const registerSchema = z.object({
  email: z.string().email('유효한 이메일을 입력하세요').max(255),
  password: z
    .string()
    .min(8, '비밀번호는 8자 이상')
    .max(128, '비밀번호는 128자 이하')
    .regex(/[A-Z]/, '대문자 1개 이상 포함')
    .regex(/[a-z]/, '소문자 1개 이상 포함')
    .regex(/[0-9]/, '숫자 1개 이상 포함')
    .regex(/[^A-Za-z0-9]/, '특수문자 1개 이상 포함'),
  name: z
    .string()
    .min(2, '이름은 2자 이상')
    .max(50, '이름은 50자 이하')
    .regex(/^[a-zA-Z가-힣\\s]+$/, '이름에 특수문자를 사용할 수 없습니다'),
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: '너무 많은 가입 시도입니다. 1시간 후 다시 시도하세요.' },
});

router.post('/register', registerLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password, name } = registerSchema.parse(req.body);

    // 이메일 중복 확인
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      // 타이밍 공격 방지: 존재 여부와 관계없이 동일한 응답 시간
      await bcrypt.hash('dummy-password', SALT_ROUNDS);
      return res.status(409).json({ error: '이미 사용 중인 이메일입니다' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    await db.query(
      'INSERT INTO users (email, password_hash, name, role, created_at) VALUES ($1, $2, $3, $4, NOW())',
      [email.toLowerCase(), passwordHash, name, 'user']
    );

    // 비밀번호 해시를 응답에 포함하지 않음
    res.status(201).json({ message: '회원가입이 완료되었습니다' });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({
        error: '입력값이 올바르지 않습니다',
        details: err.errors.map((e) => ({ field: e.path.join('.'), message: e.message })),
      });
    }
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;`,
    explanationKo: '비밀번호 정책(대소문자/숫자/특수문자), bcrypt 해싱, Rate Limiting, 타이밍 공격 방지가 적용된 회원가입 API',
    securityChecklist: [
      '[비밀번호] bcrypt(12 rounds) 해싱',
      '[비밀번호 정책] 8자 이상 + 대소문자 + 숫자 + 특수문자 필수',
      '[Rate Limiting] 시간당 5회 가입 제한 (자동 가입 방지)',
      '[타이밍 공격] 이메일 존재 여부와 관계없이 동일한 응답 시간',
      '[SQL Injection] 파라미터화 쿼리',
      '[정보 노출] 응답에 비밀번호 해시 미포함',
      '[입력 검증] 이메일/이름/비밀번호 형식 검증',
      '[이메일 정규화] 소문자 변환으로 중복 가입 방지',
    ],
    appliedDefenses: [
      'A02-Cryptographic Failures: bcrypt 12 rounds',
      'A03-Injection: 파라미터화 쿼리',
      'A04-Insecure Design: 비밀번호 복잡성 정책',
      'A07-Auth Failures: Rate Limiting + 타이밍 공격 방지',
    ],
  },

  // ── 로그인 ──
  {
    keywords: ['login', 'auth', 'signin', 'sign-in', '로그인', '인증'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET!;

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(128),
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Please try again later.' },
});

router.post('/login', loginLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await db.query(
      'SELECT id, email, password_hash, role FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    // 존재하지 않는 사용자여도 bcrypt.compare 실행 (타이밍 공격 방지)
    const hash = user.rows[0]?.password_hash ?? '$2b$12$invalid.hash.placeholder.for.timing';
    const isValid = await bcrypt.compare(password, hash);

    if (!user.rows[0] || !isValid) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다' });
    }

    const token = jwt.sign(
      { userId: user.rows[0].id, role: user.rows[0].role },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000,
    });

    res.json({ message: '로그인 성공' });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: '입력값이 올바르지 않습니다' });
    }
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;`,
    explanationKo: 'bcrypt 해싱, JWT, Rate Limiting, 타이밍 공격 방지, 보안 쿠키가 적용된 로그인 API',
    securityChecklist: [
      '[인증] bcrypt.compare로 비밀번호 검증',
      '[Rate Limiting] 15분당 5회 로그인 시도 제한',
      '[타이밍 공격] 사용자 존재 여부와 관계없이 동일 응답 시간',
      '[JWT] HS256 알고리즘 + 1시간 만료',
      '[쿠키 보안] HttpOnly + Secure + SameSite=Strict',
      '[에러 메시지] "이메일 또는 비밀번호" 통합 메시지 (계정 열거 방지)',
    ],
    appliedDefenses: [
      'A07-Auth Failures: 타이밍 공격 방지 + Rate Limiting',
      'A02-Cryptographic Failures: bcrypt + JWT HS256',
    ],
  },

  // ── 파일 업로드 ──
  {
    keywords: ['upload', 'file', '파일', '업로드', '이미지', 'image', '첨부'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs/promises';
import { authenticate } from './middleware/auth';

const UPLOAD_DIR = path.resolve('./uploads');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_TYPES: Record<string, string[]> = {
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'image/gif': ['.gif'],
  'image/webp': ['.webp'],
  'application/pdf': ['.pdf'],
};

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (_req, _file, cb) => {
    cb(null, crypto.randomBytes(20).toString('hex'));
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: 5 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExts = ALLOWED_TYPES[file.mimetype];
    if (!allowedExts || !allowedExts.includes(ext)) {
      return cb(new Error('허용되지 않는 파일 형식입니다'));
    }
    cb(null, true);
  },
});

const router = Router();

router.post('/upload', authenticate, upload.array('files', 5), async (req: Request, res: Response) => {
  try {
    const files = req.files as Express.Multer.File[];
    if (!files || files.length === 0) {
      return res.status(400).json({ error: '파일을 선택하세요' });
    }

    const results = [];
    for (const file of files) {
      const filePath = path.resolve(file.path);
      // Path Traversal 방지
      if (!filePath.startsWith(UPLOAD_DIR)) {
        await fs.unlink(filePath).catch(() => {});
        continue;
      }

      const ext = path.extname(file.originalname).toLowerCase();
      const finalPath = filePath + ext;
      await fs.rename(filePath, finalPath);

      results.push({
        filename: path.basename(finalPath),
        originalName: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
      });
    }

    res.json({ files: results });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;`,
    explanationKo: 'MIME+확장자 이중 검증, 랜덤 파일명, Path Traversal 방지, 크기/개수 제한이 적용된 파일 업로드 API',
    securityChecklist: [
      '[파일 검증] MIME 타입 + 확장자 이중 검증',
      '[파일명] 원본 파일명 비사용, 랜덤 hex 생성',
      '[Path Traversal] 업로드 디렉토리 이탈 검사',
      '[크기 제한] 파일당 10MB, 최대 5개',
      '[인증] 로그인 사용자만 업로드 가능',
    ],
    appliedDefenses: [
      'A01-Broken Access Control: 인증 필수',
      'A04-Insecure Design: 파일 타입/크기 검증',
    ],
  },

  // ── 비밀번호 변경 ──
  {
    keywords: ['비밀번호 변경', 'password change', 'password update', '비번 변경', '비밀번호 수정', 'change password'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import { authenticate } from './middleware/auth';

const router = Router();
const SALT_ROUNDS = 12;

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z
    .string()
    .min(8, '비밀번호는 8자 이상')
    .max(128)
    .regex(/[A-Z]/, '대문자 1개 이상')
    .regex(/[a-z]/, '소문자 1개 이상')
    .regex(/[0-9]/, '숫자 1개 이상')
    .regex(/[^A-Za-z0-9]/, '특수문자 1개 이상'),
}).refine((data) => data.currentPassword !== data.newPassword, {
  message: '새 비밀번호는 현재 비밀번호와 달라야 합니다',
});

const passwordChangeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: '비밀번호 변경 시도가 너무 많습니다' },
});

router.put('/password', authenticate, passwordChangeLimiter, async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword } = changePasswordSchema.parse(req.body);
    const userId = req.user!.userId;

    const user = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isValid = await bcrypt.compare(currentPassword, user.rows[0].password_hash);
    if (!isValid) {
      return res.status(401).json({ error: '현재 비밀번호가 올바르지 않습니다' });
    }

    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await db.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, userId]);

    // 비밀번호 변경 후 다른 세션 무효화 (선택사항)
    // await db.query('DELETE FROM sessions WHERE user_id = $1', [userId]);

    res.json({ message: '비밀번호가 변경되었습니다' });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({
        error: '입력값이 올바르지 않습니다',
        details: err.errors.map((e) => ({ field: e.path.join('.'), message: e.message })),
      });
    }
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;`,
    explanationKo: '현재 비밀번호 확인, 비밀번호 정책, Rate Limiting, 세션 무효화가 적용된 비밀번호 변경 API',
    securityChecklist: [
      '[인증] 현재 비밀번호 확인 필수',
      '[비밀번호 정책] 8자+대소문자+숫자+특수문자',
      '[동일 비밀번호] 현재와 동일한 비밀번호 거부',
      '[Rate Limiting] 시간당 3회 제한',
      '[해싱] bcrypt 12 rounds',
    ],
    appliedDefenses: [
      'A02-Cryptographic Failures: bcrypt 12 rounds',
      'A07-Auth Failures: 현재 비밀번호 확인 + Rate Limiting',
    ],
  },

  // ── SQL/DB 쿼리 ──
  {
    keywords: ['sql', 'query', 'database', 'db', '쿼리', '데이터베이스'],
    language: ['typescript', 'javascript'],
    code: `import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 20,
  idleTimeoutMillis: 30000,
});

async function findUserById(userId: string) {
  const result = await pool.query(
    'SELECT id, email, name, role FROM users WHERE id = $1',
    [userId]
  );
  return result.rows[0] ?? null;
}

async function searchUsers(name: string, limit: number = 20) {
  const safeName = \`%\${name}%\`;
  const safeLimit = Math.min(Math.max(1, limit), 100);
  const result = await pool.query(
    'SELECT id, email, name FROM users WHERE name ILIKE $1 LIMIT $2',
    [safeName, safeLimit]
  );
  return result.rows;
}`,
    explanationKo: 'SQL 인젝션 방지 파라미터화 쿼리, 커넥션 풀링, 결과 제한이 적용된 DB 접근 코드',
    securityChecklist: [
      '[SQL Injection] 파라미터화 쿼리 ($1, $2)',
      '[커넥션 풀링] 최대 20 커넥션',
      '[결과 제한] LIMIT 최대 100',
      '[최소 권한] 필요한 컬럼만 SELECT',
    ],
    appliedDefenses: ['A03-Injection: 파라미터화 쿼리'],
  },

  // ── JWT 미들웨어 ──
  {
    keywords: ['jwt', 'middleware', 'token', '미들웨어', '토큰', '인증 미들웨어'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET!;

interface JwtPayload { userId: string; role: string; iat: number; exp: number; }

declare global { namespace Express { interface Request { user?: JwtPayload; } } }

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], maxAge: '1h' }) as JwtPayload;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function authorize(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}`,
    explanationKo: 'JWT 알고리즘 제한, 만료 검증, RBAC 인가가 적용된 인증 미들웨어',
    securityChecklist: [
      '[JWT] 알고리즘 HS256 고정 (none 공격 차단)',
      '[만료] maxAge 1시간',
      '[RBAC] 역할 기반 인가',
      '[시크릿] 환경변수 관리',
    ],
    appliedDefenses: ['A07-Auth Failures: JWT 검증 + RBAC'],
  },

  // ── 검색 ──
  {
    keywords: ['검색', 'search', '찾기', 'find', '조회'],
    language: ['typescript', 'javascript'],
    framework: ['express'],
    code: `import { Router, Request, Response } from 'express';
import { z } from 'zod';

const router = Router();

const searchSchema = z.object({
  q: z.string().min(1).max(100).transform((v) => v.trim()),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  sort: z.enum(['latest', 'relevance', 'popular']).default('relevance'),
});

router.get('/search', async (req: Request, res: Response) => {
  try {
    const { q, page, limit, sort } = searchSchema.parse(req.query);
    const offset = (page - 1) * limit;

    // LIKE 와일드카드 이스케이프 (SQL Injection 방지)
    const escaped = q.replace(/[%_\\\\]/g, '\\\\$&');

    const orderBy = {
      latest: 'p.created_at DESC',
      relevance: 'ts_rank(to_tsvector(p.title || p.content), plainto_tsquery($1)) DESC',
      popular: 'p.view_count DESC',
    }[sort];

    const result = await db.query(
      \`SELECT p.id, p.title, p.category, p.created_at, u.name as author
       FROM posts p JOIN users u ON p.author_id = u.id
       WHERE p.title ILIKE $1 OR p.content ILIKE $1
       ORDER BY \${orderBy} LIMIT $2 OFFSET $3\`,
      [\`%\${escaped}%\`, limit, offset]
    );

    const countResult = await db.query(
      'SELECT COUNT(*) FROM posts WHERE title ILIKE $1 OR content ILIKE $1',
      [\`%\${escaped}%\`]
    );

    res.json({
      results: result.rows,
      total: parseInt(countResult.rows[0].count, 10),
      page,
      limit,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: '검색어를 확인하세요' });
    }
    console.error('Search error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;`,
    explanationKo: 'LIKE 이스케이프, 파라미터화 쿼리, 페이지네이션 제한, 정렬 화이트리스트가 적용된 검색 API',
    securityChecklist: [
      '[SQL Injection] LIKE 와일드카드(%, _) 이스케이프',
      '[SQL Injection] 파라미터화 쿼리',
      '[DoS 방지] 페이지당 최대 50건 제한',
      '[정렬 인젝션] ORDER BY를 화이트리스트로 제한',
      '[입력 검증] 검색어 100자 제한',
    ],
    appliedDefenses: ['A03-Injection: 파라미터화 쿼리 + LIKE 이스케이프 + ORDER BY 화이트리스트'],
  },

  // ════════════════════════════════════════════
  // 프론트엔드 HTML/JS 시큐어 템플릿
  // ════════════════════════════════════════════

  // ── 로그인 페이지 (HTML) ──
  {
    keywords: ['로그인', '로그인 페이지', 'login', 'login page', 'signin', '로그인 폼', 'login form', '인증 페이지'],
    language: ['html', 'javascript'],
    code: `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <!-- [보안] Content Security Policy: 인라인 스크립트/외부 리소스 제한 -->
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.example.com;">
  <!-- [보안] 클릭재킹 방지 -->
  <meta http-equiv="X-Frame-Options" content="DENY">
  <meta http-equiv="X-Content-Type-Options" content="nosniff">
  <title>로그인</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Pretendard', -apple-system, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .login-container { background: white; padding: 2.5rem; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); width: 100%; max-width: 400px; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #1a1a1a; }
    .subtitle { color: #888; margin-bottom: 2rem; font-size: 0.9rem; }
    .form-group { margin-bottom: 1.25rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; color: #333; margin-bottom: 0.4rem; }
    input[type="email"], input[type="password"] { width: 100%; padding: 0.75rem 1rem; border: 1.5px solid #e0e0e0; border-radius: 8px; font-size: 0.95rem; transition: border-color 0.2s; }
    input:focus { outline: none; border-color: #4A90D9; }
    .input-error { border-color: #e74c3c !important; animation: shake 0.3s; }
    @keyframes shake { 0%,100% { transform: translateX(0); } 25% { transform: translateX(-4px); } 75% { transform: translateX(4px); } }
    .error-text { color: #e74c3c; font-size: 0.8rem; margin-top: 0.3rem; display: none; }
    .error-text.visible { display: block; }
    .options { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; font-size: 0.85rem; }
    .options a { color: #4A90D9; text-decoration: none; }
    .btn-login { width: 100%; padding: 0.8rem; background: #4A90D9; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
    .btn-login:hover { background: #357ABD; }
    .btn-login:disabled { background: #ccc; cursor: not-allowed; }
    .divider { text-align: center; margin: 1.5rem 0; color: #aaa; font-size: 0.85rem; position: relative; }
    .divider::before, .divider::after { content: ''; position: absolute; top: 50%; width: 40%; height: 1px; background: #e0e0e0; }
    .divider::before { left: 0; }
    .divider::after { right: 0; }
    .social-buttons { display: flex; gap: 0.75rem; }
    .btn-social { flex: 1; padding: 0.7rem; border: 1.5px solid #e0e0e0; border-radius: 8px; background: white; cursor: pointer; font-size: 0.85rem; font-weight: 500; transition: background 0.2s; }
    .btn-social:hover { background: #f9f9f9; }
    .alert { padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; display: none; }
    .alert-error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .alert-success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .alert.visible { display: block; }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>로그인</h1>
    <p class="subtitle">계정에 로그인하세요</p>

    <div id="alert" class="alert" role="alert"></div>

    <!-- [보안] autocomplete 설정으로 브라우저 비밀번호 관리자 지원 -->
    <form id="loginForm" novalidate>
      <!-- [보안] CSRF 토큰 (서버에서 동적 발급 - DOMContentLoaded 시 자동 획득) -->
      <input type="hidden" name="_csrf" id="csrfToken" value="">

      <div class="form-group">
        <label for="email">이메일</label>
        <input type="email" id="email" name="email"
               placeholder="you@example.com"
               autocomplete="email"
               required maxlength="255">
        <p class="error-text" id="emailError"></p>
      </div>

      <div class="form-group">
        <label for="password">비밀번호</label>
        <!-- [보안] type="password"로 마스킹 + autocomplete="current-password" -->
        <input type="password" id="password" name="password"
               placeholder="비밀번호 입력"
               autocomplete="current-password"
               required minlength="8" maxlength="128">
        <p class="error-text" id="passwordError"></p>
      </div>

      <div class="options">
        <label style="display:flex;align-items:center;gap:0.3rem;cursor:pointer;">
          <input type="checkbox" id="remember"> 로그인 유지
        </label>
        <a href="/forgot-password">비밀번호 찾기</a>
      </div>

      <button type="submit" class="btn-login" id="submitBtn">로그인</button>
    </form>

    <div class="divider">또는</div>

    <div class="social-buttons">
      <button class="btn-social" onclick="socialLogin('google')">Google</button>
      <button class="btn-social" onclick="socialLogin('kakao')">카카오</button>
    </div>
  </div>

  <script>
    // ── [보안] 입력값 검증 유틸 ──
    function sanitizeInput(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    function isValidEmail(email) {
      return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) && email.length <= 255;
    }

    // ── [보안] Rate Limiting (클라이언트 측 보조) ──
    const loginAttempts = { count: 0, lastAttempt: 0 };
    const MAX_ATTEMPTS = 5;
    const LOCKOUT_MS = 15 * 60 * 1000;

    function isRateLimited() {
      const now = Date.now();
      if (now - loginAttempts.lastAttempt > LOCKOUT_MS) {
        loginAttempts.count = 0;
      }
      return loginAttempts.count >= MAX_ATTEMPTS;
    }

    // ── [보안] 에러/성공 메시지 표시 (textContent로 XSS 방지) ──
    function showAlert(type, message) {
      const alert = document.getElementById('alert');
      alert.className = 'alert alert-' + type + ' visible';
      alert.textContent = message;
    }

    function showFieldError(fieldId, message) {
      const input = document.getElementById(fieldId);
      const error = document.getElementById(fieldId + 'Error');
      input.classList.add('input-error');
      error.textContent = message;
      error.classList.add('visible');
    }

    function clearErrors() {
      document.querySelectorAll('.input-error').forEach(el => el.classList.remove('input-error'));
      document.querySelectorAll('.error-text').forEach(el => {
        el.classList.remove('visible');
        el.textContent = '';
      });
      const alert = document.getElementById('alert');
      alert.classList.remove('visible');
    }

    // ── [보안] 폼 제출 처리 ──
    document.getElementById('loginForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      clearErrors();

      // [보안] Rate Limiting 체크
      if (isRateLimited()) {
        showAlert('error', '로그인 시도가 너무 많습니다. 15분 후 다시 시도하세요.');
        return;
      }

      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;

      // [보안] 클라이언트 측 입력 검증
      let hasError = false;
      if (!email) {
        showFieldError('email', '이메일을 입력하세요');
        hasError = true;
      } else if (!isValidEmail(email)) {
        showFieldError('email', '유효한 이메일 형식이 아닙니다');
        hasError = true;
      }
      if (!password) {
        showFieldError('password', '비밀번호를 입력하세요');
        hasError = true;
      } else if (password.length < 8) {
        showFieldError('password', '비밀번호는 8자 이상입니다');
        hasError = true;
      }
      if (hasError) return;

      const submitBtn = document.getElementById('submitBtn');
      submitBtn.disabled = true;
      submitBtn.textContent = '로그인 중...';

      try {
        // [보안] HTTPS API 호출 + credentials: 'same-origin'
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            // [보안] CSRF 토큰 헤더
            'X-CSRF-Token': document.getElementById('csrfToken').value,
          },
          body: JSON.stringify({ email, password }),
          credentials: 'same-origin',
        });

        const data = await res.json();

        loginAttempts.count++;
        loginAttempts.lastAttempt = Date.now();

        if (res.ok) {
          // [보안] 로그인 후 비밀번호 필드 초기화
          document.getElementById('password').value = '';
          showAlert('success', '로그인 성공! 리다이렉트 중...');

          // [보안] Open Redirect 방지: 허용된 도메인만 리다이렉트
          const redirectUrl = new URL(data.redirectUrl || '/', window.location.origin);
          if (redirectUrl.origin === window.location.origin) {
            setTimeout(() => window.location.href = redirectUrl.pathname, 1000);
          } else {
            setTimeout(() => window.location.href = '/', 1000);
          }
        } else {
          // [보안] 서버 에러 메시지를 textContent로 표시 (XSS 방지)
          showAlert('error', data.error || '이메일 또는 비밀번호가 올바르지 않습니다');
        }
      } catch (err) {
        // [보안] 네트워크 에러에 상세 정보 미노출
        showAlert('error', '서버에 연결할 수 없습니다. 잠시 후 다시 시도하세요.');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = '로그인';
      }
    });

    // [보안] Enter 키 로그인
    document.getElementById('password').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') document.getElementById('loginForm').requestSubmit();
    });

    // [보안] 소셜 로그인 - OAuth state 파라미터 포함
    function socialLogin(provider) {
      const state = crypto.getRandomValues(new Uint8Array(16))
        .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
      sessionStorage.setItem('oauth_state', state);
      window.location.href = '/api/auth/' + encodeURIComponent(provider) + '?state=' + state;
    }

    // [보안] CSRF 토큰을 서버에서 동적으로 획득
    async function fetchCsrfToken() {
      try {
        const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
        if (res.ok) {
          const { token } = await res.json();
          document.getElementById('csrfToken').value = token;
        }
      } catch (e) { console.warn('CSRF token fetch failed'); }
    }
    window.addEventListener('DOMContentLoaded', fetchCsrfToken);
  </script>
</body>
</html>`,
    explanationKo: 'CSP 헤더, XSS 방지(textContent), CSRF 토큰(서버 동적 발급), Open Redirect 방지, 클라이언트+서버 Rate Limiting, OAuth state가 적용된 시큐어 로그인 페이지',
    securityChecklist: [
      '[XSS 방지] 모든 동적 텍스트를 textContent로 삽입 (innerHTML 미사용)',
      '[CSP] Content-Security-Policy 메타 태그로 인라인 스크립트/외부 리소스 차단 (서버 응답 헤더로도 설정 필요)',
      '[클릭재킹] X-Frame-Options: DENY (메타 태그 + 서버 응답 헤더 설정 필요)',
      '[CSRF] 서버 동적 CSRF 토큰 발급(fetchCsrfToken) + X-CSRF-Token 헤더 전송',
      '[입력 검증] 이메일 형식/길이, 비밀번호 최소 길이 클라이언트 검증 (서버측 검증도 필수)',
      '[Rate Limiting] 클라이언트 측 15분/5회 제한 (서버측 express-rate-limit 필수 구현)',
      '[비밀번호 보호] type="password" + autocomplete="current-password"',
      '[Open Redirect 방지] 리다이렉트 URL이 같은 origin인지 확인',
      '[에러 메시지] "이메일 또는 비밀번호가 올바르지 않습니다" 통합 메시지',
      '[소셜 로그인] OAuth state 파라미터 생성 (서버 콜백에서 반드시 state 검증 필요 - app.get("/auth/callback", verifyState, ...))',
      '[자격증명] credentials: same-origin + HTTPS API 호출',
      '[비밀번호 초기화] 로그인 후 password 필드 값 제거',
    ],
    appliedDefenses: [
      'A03-XSS: textContent + CSP 헤더 (서버 응답 헤더로도 설정 필요)',
      'A05-Misconfiguration: X-Frame-Options, X-Content-Type-Options (서버 응답 헤더 설정 필요)',
      'A07-Auth Failures: Rate Limiting(서버측 필수) + CSRF 토큰(서버 동적 발급)',
      'A01-Broken Access Control: Open Redirect 방지',
    ],
  },

  // ── 게시글 작성 페이지 (HTML) ──
  {
    keywords: ['게시글', '게시판', '글쓰기', '글 작성', 'post', 'board', 'article', 'write', '게시글 작성 페이지', '게시판 페이지', '글쓰기 페이지'],
    language: ['html', 'javascript'],
    code: `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https://api.example.com;">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <title>게시글 작성</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Pretendard', -apple-system, sans-serif; background: #f5f5f5; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #1a1a1a; }
    .form-group { margin-bottom: 1.25rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; color: #333; margin-bottom: 0.4rem; }
    input[type="text"], select, textarea { width: 100%; padding: 0.75rem 1rem; border: 1.5px solid #e0e0e0; border-radius: 8px; font-size: 0.95rem; font-family: inherit; }
    textarea { min-height: 300px; resize: vertical; }
    .char-count { text-align: right; font-size: 0.8rem; color: #888; margin-top: 0.3rem; }
    .char-count.warning { color: #e74c3c; }
    .btn-group { display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.5rem; }
    .btn { padding: 0.7rem 1.5rem; border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    .btn-primary { background: #4A90D9; color: white; }
    .btn-secondary { background: #e0e0e0; color: #333; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .alert { padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; display: none; }
    .alert-error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .alert.visible { display: block; }
    .file-upload { border: 2px dashed #e0e0e0; border-radius: 8px; padding: 1.5rem; text-align: center; cursor: pointer; color: #888; }
    .file-list { margin-top: 0.5rem; }
    .file-item { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0; font-size: 0.85rem; }
    .file-remove { color: #e74c3c; cursor: pointer; background: none; border: none; }
  </style>
</head>
<body>
  <div class="container">
    <h1>게시글 작성</h1>
    <div id="alert" class="alert alert-error" role="alert"></div>

    <form id="postForm" novalidate>
      <!-- [보안] CSRF 토큰 (서버에서 동적 발급 - DOMContentLoaded 시 자동 획득) -->
      <input type="hidden" name="_csrf" id="csrfToken" value="">

      <div class="form-group">
        <label for="title">제목</label>
        <!-- [보안] maxlength로 클라이언트 제한 + 서버에서도 200자 제한 -->
        <input type="text" id="title" name="title"
               placeholder="제목을 입력하세요" required maxlength="200">
        <div class="char-count"><span id="titleCount">0</span>/200</div>
      </div>

      <div class="form-group">
        <label for="category">카테고리</label>
        <!-- [보안] 카테고리를 select로 제한 (자유 입력 차단) -->
        <select id="category" name="category">
          <option value="general">일반</option>
          <option value="tech">기술</option>
          <option value="question">질문</option>
          <option value="notice">공지</option>
        </select>
      </div>

      <div class="form-group">
        <label for="content">내용</label>
        <textarea id="content" name="content"
                  placeholder="내용을 입력하세요" required maxlength="50000"></textarea>
        <div class="char-count"><span id="contentCount">0</span>/50,000</div>
      </div>

      <div class="form-group">
        <label>첨부파일</label>
        <div class="file-upload" id="dropZone">
          클릭하거나 파일을 드래그하세요 (최대 5개, 10MB 이하)
          <!-- [보안] accept로 허용 파일타입 제한 -->
          <input type="file" id="fileInput" multiple
                 accept=".jpg,.jpeg,.png,.gif,.webp,.pdf"
                 style="display:none;">
        </div>
        <div class="file-list" id="fileList"></div>
      </div>

      <div class="btn-group">
        <button type="button" class="btn btn-secondary" onclick="history.back()">취소</button>
        <button type="submit" class="btn btn-primary" id="submitBtn">작성하기</button>
      </div>
    </form>
  </div>

  <script>
    const MAX_TITLE = 200;
    const MAX_CONTENT = 50000;
    const MAX_FILES = 5;
    const MAX_FILE_SIZE = 10 * 1024 * 1024;
    const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];

    let selectedFiles = [];

    // ── [보안] 글자 수 카운트 ──
    document.getElementById('title').addEventListener('input', function() {
      const count = this.value.length;
      const el = document.getElementById('titleCount');
      el.textContent = count;
      el.parentElement.classList.toggle('warning', count > MAX_TITLE * 0.9);
    });
    document.getElementById('content').addEventListener('input', function() {
      const count = this.value.length;
      const el = document.getElementById('contentCount');
      el.textContent = count.toLocaleString();
      el.parentElement.classList.toggle('warning', count > MAX_CONTENT * 0.9);
    });

    // ── [보안] 파일 업로드 검증 ──
    document.getElementById('dropZone').addEventListener('click', () => document.getElementById('fileInput').click());
    document.getElementById('fileInput').addEventListener('change', function(e) {
      addFiles(Array.from(e.target.files));
      this.value = '';
    });
    document.getElementById('dropZone').addEventListener('dragover', e => { e.preventDefault(); e.currentTarget.style.borderColor = '#4A90D9'; });
    document.getElementById('dropZone').addEventListener('dragleave', e => { e.currentTarget.style.borderColor = '#e0e0e0'; });
    document.getElementById('dropZone').addEventListener('drop', e => {
      e.preventDefault();
      e.currentTarget.style.borderColor = '#e0e0e0';
      addFiles(Array.from(e.dataTransfer.files));
    });

    function addFiles(files) {
      for (const file of files) {
        if (selectedFiles.length >= MAX_FILES) {
          showAlert('최대 ' + MAX_FILES + '개까지 업로드할 수 있습니다');
          break;
        }
        // [보안] 파일 타입 검증
        if (!ALLOWED_TYPES.includes(file.type)) {
          showAlert('허용되지 않는 파일 형식입니다: ' + sanitize(file.name));
          continue;
        }
        // [보안] 파일 크기 검증
        if (file.size > MAX_FILE_SIZE) {
          showAlert('파일 크기가 10MB를 초과합니다: ' + sanitize(file.name));
          continue;
        }
        selectedFiles.push(file);
      }
      renderFileList();
    }

    function removeFile(idx) {
      selectedFiles.splice(idx, 1);
      renderFileList();
    }

    function renderFileList() {
      const list = document.getElementById('fileList');
      // [보안] innerHTML 대신 DOM API로 렌더링 (XSS 방지)
      list.innerHTML = '';
      selectedFiles.forEach((file, idx) => {
        const item = document.createElement('div');
        item.className = 'file-item';
        const name = document.createElement('span');
        name.textContent = file.name + ' (' + (file.size / 1024 / 1024).toFixed(1) + 'MB)';
        const btn = document.createElement('button');
        btn.className = 'file-remove';
        btn.textContent = '삭제';
        btn.onclick = () => removeFile(idx);
        item.appendChild(name);
        item.appendChild(btn);
        list.appendChild(item);
      });
    }

    // ── [보안] XSS 방지 유틸 ──
    function sanitize(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    function showAlert(msg) {
      const alert = document.getElementById('alert');
      alert.textContent = msg;
      alert.classList.add('visible');
      setTimeout(() => alert.classList.remove('visible'), 5000);
    }

    // ── [보안] 폼 제출 ──
    document.getElementById('postForm').addEventListener('submit', async function(e) {
      e.preventDefault();

      const title = document.getElementById('title').value.trim();
      const content = document.getElementById('content').value.trim();
      const category = document.getElementById('category').value;

      // [보안] 입력 검증
      if (!title || title.length > MAX_TITLE) {
        showAlert('제목을 확인하세요 (1~200자)');
        return;
      }
      if (!content || content.length > MAX_CONTENT) {
        showAlert('내용을 확인하세요 (1~50,000자)');
        return;
      }

      const submitBtn = document.getElementById('submitBtn');
      submitBtn.disabled = true;
      submitBtn.textContent = '작성 중...';

      try {
        const formData = new FormData();
        formData.append('title', title);
        formData.append('content', content);
        formData.append('category', category);
        for (const file of selectedFiles) {
          formData.append('files', file);
        }

        const res = await fetch('/api/posts', {
          method: 'POST',
          headers: {
            'X-CSRF-Token': document.getElementById('csrfToken').value,
          },
          body: formData,
          credentials: 'same-origin',
        });

        if (res.ok) {
          const data = await res.json();
          // [보안] Open Redirect 방지
          window.location.href = '/posts/' + encodeURIComponent(data.post.id);
        } else {
          const data = await res.json();
          showAlert(data.error || '게시글 작성에 실패했습니다');
        }
      } catch (err) {
        showAlert('서버에 연결할 수 없습니다');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = '작성하기';
      }
    });

    // [보안] CSRF 토큰을 서버에서 동적으로 획득
    async function fetchCsrfToken() {
      try {
        const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
        if (res.ok) {
          const { token } = await res.json();
          document.getElementById('csrfToken').value = token;
        }
      } catch (e) { console.warn('CSRF token fetch failed'); }
    }
    window.addEventListener('DOMContentLoaded', fetchCsrfToken);
  </script>
</body>
</html>`,
    explanationKo: 'CSP, XSS 방지(textContent/DOM API), CSRF 토큰(서버 동적 발급), 입력검증, 파일타입/크기 검증이 적용된 시큐어 게시글 작성 페이지',
    securityChecklist: [
      '[XSS] 동적 텍스트를 textContent/DOM API로 삽입 (innerHTML 최소화)',
      '[CSP] Content-Security-Policy 메타 태그로 외부 스크립트 차단 (서버 응답 헤더로도 설정 필요)',
      '[CSRF] 서버 동적 CSRF 토큰 발급(fetchCsrfToken) + X-CSRF-Token 헤더 전송',
      '[입력 검증] 제목 200자, 내용 50000자 클라이언트 검증 (서버측 검증도 필수)',
      '[파일 검증] MIME 타입 + 확장자 + 10MB 크기 제한',
      '[파일 개수] 최대 5개 제한',
      '[카테고리] select로 고정값만 허용 (자유입력 차단)',
      '[클릭재킹] X-Frame-Options: DENY',
      '[Open Redirect] 리다이렉트 시 encodeURIComponent 사용',
    ],
    appliedDefenses: [
      'A03-XSS: textContent + CSP',
      'A04-Insecure Design: 파일 타입/크기 제한',
      'A05-Misconfiguration: 보안 헤더',
    ],
  },

  // ── 회원가입 페이지 (HTML) ──
  {
    keywords: ['회원가입', '회원가입 페이지', 'register', 'signup', 'sign-up', '가입', '가입 페이지', '계정 생성'],
    language: ['html', 'javascript'],
    code: `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self';">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <title>회원가입</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Pretendard', -apple-system, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .register-container { background: white; padding: 2.5rem; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); width: 100%; max-width: 440px; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .subtitle { color: #888; margin-bottom: 2rem; font-size: 0.9rem; }
    .form-group { margin-bottom: 1.25rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; color: #333; margin-bottom: 0.4rem; }
    input { width: 100%; padding: 0.75rem 1rem; border: 1.5px solid #e0e0e0; border-radius: 8px; font-size: 0.95rem; }
    input:focus { outline: none; border-color: #4A90D9; }
    .error-text { color: #e74c3c; font-size: 0.8rem; margin-top: 0.3rem; min-height: 1rem; }
    .password-strength { height: 4px; border-radius: 2px; margin-top: 0.3rem; transition: all 0.3s; }
    .strength-text { font-size: 0.75rem; margin-top: 0.2rem; }
    .btn-register { width: 100%; padding: 0.8rem; background: #4A90D9; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
    .btn-register:disabled { background: #ccc; cursor: not-allowed; }
    .alert { padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; display: none; }
    .alert-error { background: #fef2f2; color: #dc2626; }
    .alert-success { background: #f0fdf4; color: #16a34a; }
    .alert.visible { display: block; }
    .pw-requirements { font-size: 0.75rem; color: #888; margin-top: 0.3rem; }
    .pw-requirements span.met { color: #16a34a; }
    .pw-requirements span.unmet { color: #e74c3c; }
  </style>
</head>
<body>
  <div class="register-container">
    <h1>회원가입</h1>
    <p class="subtitle">새 계정을 만드세요</p>
    <div id="alert" class="alert" role="alert"></div>

    <form id="registerForm" novalidate>
      <!-- [보안] CSRF 토큰 (서버에서 동적 발급 - DOMContentLoaded 시 자동 획득) -->
      <input type="hidden" name="_csrf" id="csrfToken" value="">

      <div class="form-group">
        <label for="name">이름</label>
        <input type="text" id="name" name="name" placeholder="이름" required
               autocomplete="name" maxlength="50">
        <p class="error-text" id="nameError"></p>
      </div>

      <div class="form-group">
        <label for="email">이메일</label>
        <input type="email" id="email" name="email" placeholder="you@example.com" required
               autocomplete="email" maxlength="255">
        <p class="error-text" id="emailError"></p>
      </div>

      <div class="form-group">
        <label for="password">비밀번호</label>
        <!-- [보안] autocomplete="new-password"로 브라우저 비밀번호 생성 유도 -->
        <input type="password" id="password" name="password" placeholder="8자 이상" required
               autocomplete="new-password" minlength="8" maxlength="128">
        <div class="password-strength" id="strengthBar"></div>
        <div class="strength-text" id="strengthText"></div>
        <div class="pw-requirements" id="pwRequirements">
          <span id="reqLength" class="unmet">8자 이상</span> ·
          <span id="reqUpper" class="unmet">대문자</span> ·
          <span id="reqLower" class="unmet">소문자</span> ·
          <span id="reqNumber" class="unmet">숫자</span> ·
          <span id="reqSpecial" class="unmet">특수문자</span>
        </div>
        <p class="error-text" id="passwordError"></p>
      </div>

      <div class="form-group">
        <label for="passwordConfirm">비밀번호 확인</label>
        <input type="password" id="passwordConfirm" placeholder="비밀번호 재입력" required
               autocomplete="new-password">
        <p class="error-text" id="passwordConfirmError"></p>
      </div>

      <button type="submit" class="btn-register" id="submitBtn">가입하기</button>
    </form>
  </div>

  <script>
    // ── [보안] 비밀번호 강도 실시간 체크 ──
    document.getElementById('password').addEventListener('input', function() {
      const pw = this.value;
      const checks = {
        length: pw.length >= 8,
        upper: /[A-Z]/.test(pw),
        lower: /[a-z]/.test(pw),
        number: /[0-9]/.test(pw),
        special: /[^A-Za-z0-9]/.test(pw),
      };

      document.getElementById('reqLength').className = checks.length ? 'met' : 'unmet';
      document.getElementById('reqUpper').className = checks.upper ? 'met' : 'unmet';
      document.getElementById('reqLower').className = checks.lower ? 'met' : 'unmet';
      document.getElementById('reqNumber').className = checks.number ? 'met' : 'unmet';
      document.getElementById('reqSpecial').className = checks.special ? 'met' : 'unmet';

      const score = Object.values(checks).filter(Boolean).length;
      const bar = document.getElementById('strengthBar');
      const text = document.getElementById('strengthText');
      const colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60'];
      const labels = ['매우 약함', '약함', '보통', '강함', '매우 강함'];
      bar.style.width = (score * 20) + '%';
      bar.style.background = colors[score - 1] || '#e0e0e0';
      text.textContent = pw ? labels[score - 1] || '' : '';
      text.style.color = colors[score - 1] || '#888';
    });

    // ── [보안] 폼 제출 ──
    document.getElementById('registerForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      clearErrors();

      const name = document.getElementById('name').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const confirm = document.getElementById('passwordConfirm').value;

      let valid = true;

      // [보안] 이름 검증: 특수문자 차단
      if (!name || name.length < 2) {
        showFieldError('name', '이름은 2자 이상 입력하세요');
        valid = false;
      } else if (!/^[a-zA-Z가-힣\\s]+$/.test(name)) {
        showFieldError('name', '이름에 특수문자를 사용할 수 없습니다');
        valid = false;
      }

      if (!email || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) {
        showFieldError('email', '유효한 이메일을 입력하세요');
        valid = false;
      }

      // [보안] 비밀번호 복잡성 검증
      if (password.length < 8) {
        showFieldError('password', '비밀번호는 8자 이상이어야 합니다');
        valid = false;
      } else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
        showFieldError('password', '대소문자, 숫자, 특수문자를 모두 포함하세요');
        valid = false;
      }

      if (password !== confirm) {
        showFieldError('passwordConfirm', '비밀번호가 일치하지 않습니다');
        valid = false;
      }

      if (!valid) return;

      const btn = document.getElementById('submitBtn');
      btn.disabled = true;
      btn.textContent = '가입 중...';

      try {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': document.getElementById('csrfToken').value,
          },
          body: JSON.stringify({ name, email, password }),
          credentials: 'same-origin',
        });

        const data = await res.json();
        if (res.ok) {
          // [보안] 가입 후 비밀번호 필드 초기화
          document.getElementById('password').value = '';
          document.getElementById('passwordConfirm').value = '';
          showAlert('success', '가입이 완료되었습니다! 로그인 페이지로 이동합니다.');
          setTimeout(() => window.location.href = '/login', 2000);
        } else {
          showAlert('error', data.error || '가입에 실패했습니다');
        }
      } catch {
        showAlert('error', '서버에 연결할 수 없습니다');
      } finally {
        btn.disabled = false;
        btn.textContent = '가입하기';
      }
    });

    function showAlert(type, msg) {
      const el = document.getElementById('alert');
      el.className = 'alert alert-' + type + ' visible';
      el.textContent = msg;
    }
    function showFieldError(id, msg) {
      document.getElementById(id + 'Error').textContent = msg;
    }
    function clearErrors() {
      document.querySelectorAll('.error-text').forEach(el => el.textContent = '');
      document.getElementById('alert').classList.remove('visible');
    }

    // [보안] CSRF 토큰을 서버에서 동적으로 획득
    async function fetchCsrfToken() {
      try {
        const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
        if (res.ok) {
          const { token } = await res.json();
          document.getElementById('csrfToken').value = token;
        }
      } catch (e) { console.warn('CSRF token fetch failed'); }
    }
    window.addEventListener('DOMContentLoaded', fetchCsrfToken);
  </script>
</body>
</html>`,
    explanationKo: '비밀번호 강도 표시기, 복잡성 정책, CSP, CSRF 토큰(서버 동적 발급), XSS 방지가 적용된 시큐어 회원가입 페이지',
    securityChecklist: [
      '[비밀번호 정책] 8자+대소문자+숫자+특수문자 실시간 검증',
      '[비밀번호 강도] 실시간 강도 표시기 (매우약함~매우강함)',
      '[XSS] textContent로 동적 텍스트 삽입',
      '[CSP] Content-Security-Policy 헤더 (서버 응답 헤더로도 설정 필요)',
      '[CSRF] CSRF 토큰 + X-CSRF-Token 헤더',
      '[autocomplete] new-password로 브라우저 비밀번호 생성 유도',
      '[이름 검증] 특수문자 차단 (스크립트 삽입 방지)',
      '[비밀번호 초기화] 가입 후 password 필드 값 제거',
      '[CSRF] 서버 동적 CSRF 토큰 발급(fetchCsrfToken) + X-CSRF-Token 헤더 전송',
    ],
    appliedDefenses: [
      'A03-XSS: textContent + CSP',
      'A07-Auth Failures: 비밀번호 복잡성 정책',
      'A01-CSRF: 서버 동적 토큰 발급 + 검증',
    ],
  },
];

// ─── 보안 주장 동적 검증 ───

interface ValidatedClaim {
  claim: string;
  status: 'implemented' | 'partial' | 'missing';
}

const CLAIM_VERIFICATION_PATTERNS: Array<{
  keyword: RegExp;
  implementedPattern: RegExp;
  partialPattern?: RegExp;
}> = [
  {
    keyword: /\bXSS\b|innerHTML|textContent/i,
    implementedPattern: /textContent|innerText|DOMPurify\.sanitize/,
    partialPattern: /innerHTML/,
  },
  {
    keyword: /\bCSP\b|Content-Security-Policy/i,
    implementedPattern: /Content-Security-Policy/,
  },
  {
    keyword: /\bCSRF\b|csrf/i,
    implementedPattern: /fetchCsrfToken|\/api\/csrf-token|csrfProtection|csurf/,
    partialPattern: /name=["']_csrf["']|X-CSRF-Token/,
  },
  {
    keyword: /Rate\s*Limit/i,
    implementedPattern: /rateLimit\s*\(|express-rate-limit|rateLimiter/,
    partialPattern: /loginAttempts|MAX_ATTEMPTS|isRateLimited/,
  },
  {
    keyword: /\bOAuth\b.*state|state.*OAuth/i,
    implementedPattern: /req\.session\.(?:oauth|state)|verifyState|state\s*!==\s*req/,
    partialPattern: /oauth_state|sessionStorage.*state|getRandomValues/,
  },
  {
    keyword: /X-Frame|클릭재킹/i,
    implementedPattern: /X-Frame-Options/,
  },
  {
    keyword: /비밀번호\s*(?:보호|정책)|password.*policy/i,
    implementedPattern: /type=["']password["']/,
  },
  {
    keyword: /입력\s*검증|input.*valid/i,
    implementedPattern: /\.test\(|z\.string\(|z\.object\(|validate|schema/i,
    partialPattern: /minLength|maxLength|\.min\(|\.max\(/,
  },
  {
    keyword: /에러\s*메시지|통합.*메시지/i,
    implementedPattern: /올바르지 않습니다|invalid credentials|generic.*error/i,
  },
  {
    keyword: /Open\s*Redirect|리다이렉트\s*방지/i,
    implementedPattern: /\.origin\s*===|new URL\(/,
  },
  {
    keyword: /서버.*헤더|응답.*헤더/i,
    implementedPattern: /res\.setHeader|helmet|app\.use.*header/i,
    partialPattern: /meta\s+http-equiv/i,
  },
  {
    keyword: /파일\s*검증|MIME|파일.*크기/i,
    implementedPattern: /allowedTypes|ALLOWED_TYPES|file\.type|file\.size/i,
  },
];

export function validateSecurityClaims(code: string, claims: string[]): ValidatedClaim[] {
  return claims.map((claim) => {
    for (const pattern of CLAIM_VERIFICATION_PATTERNS) {
      if (!pattern.keyword.test(claim)) continue;

      if (pattern.implementedPattern.test(code)) {
        return { claim, status: 'implemented' as const };
      }
      if (pattern.partialPattern && pattern.partialPattern.test(code)) {
        return { claim, status: 'partial' as const };
      }
      return { claim, status: 'missing' as const };
    }
    return { claim, status: 'implemented' as const };
  });
}

export function handleGenerateSecure(input: GenerateSecureInput) {
  const searchText = ((input.task ?? '') + ' ' + (input.vulnerable_code ?? '')).toLowerCase();

  let bestTemplate: SecureTemplate | undefined;
  let bestScore = 0;

  for (const template of SECURE_TEMPLATES) {
    if (!template.language.includes(input.language)) continue;
    if (input.framework && template.framework && !template.framework.includes(input.framework)) continue;

    let score = 0;
    for (const kw of template.keywords) {
      if (searchText.includes(kw.toLowerCase())) score += 2;
    }
    for (const kw of template.keywords) {
      for (const word of searchText.split(/\s+/)) {
        if (word === kw.toLowerCase()) score += 3;
      }
    }
    if (score > bestScore) {
      bestScore = score;
      bestTemplate = template;
    }
  }

  const lines: string[] = [];

  if (!bestTemplate || bestScore === 0) {
    lines.push('## 🔒 시큐어코딩 가이드');
    lines.push('');
    lines.push(`요청하신 기능: **${input.task ?? '(미지정)'}**`);
    lines.push('');
    lines.push('내장 템플릿이 없는 기능입니다. 아래 시큐어코딩 체크리스트를 적용하여 코드를 작성하세요:');
    lines.push('');
    lines.push('### 필수 적용 체크리스트');
    lines.push('- [ ] **입력 검증**: 모든 외부 입력을 zod/joi 스키마로 검증');
    lines.push('- [ ] **SQL 인젝션 방지**: 파라미터화된 쿼리 사용 ($1, $2)');
    lines.push('- [ ] **XSS 방지**: HTML 출력 시 이스케이프 또는 DOMPurify 적용');
    lines.push('- [ ] **인증**: 로그인 필요 엔드포인트에 authenticate 미들웨어');
    lines.push('- [ ] **인가**: 본인 리소스만 수정/삭제 (IDOR 방지)');
    lines.push('- [ ] **에러 처리**: 클라이언트에 상세 에러 미전송');
    lines.push('- [ ] **Rate Limiting**: 민감 엔드포인트에 속도 제한');
    lines.push('- [ ] **시크릿 관리**: 하드코딩 금지, 환경변수 사용');
    lines.push('- [ ] **HTTPS**: 모든 외부 통신은 HTTPS');
    lines.push('- [ ] **최소 권한**: SELECT에서 필요한 컬럼만, 최소 DB 권한');
  } else {
    lines.push('## 🔒 시큐어코딩이 적용된 코드');
    lines.push('');
    lines.push(`**요청 기능**: ${input.task ?? ''}`);
    lines.push(`**설명**: ${bestTemplate.explanationKo}`);
    lines.push('');
    lines.push('### 🛡️ 적용된 보안 방어');
    lines.push('');
    for (const d of bestTemplate.appliedDefenses) {
      lines.push(`- **${d}**`);
    }
    lines.push('');
    const validated = validateSecurityClaims(bestTemplate.code, bestTemplate.securityChecklist);
    lines.push('### 보안 체크리스트 (코드 검증 결과)');
    lines.push('');
    for (const v of validated) {
      const icon = v.status === 'implemented' ? '✅' : v.status === 'partial' ? '⚠️' : '❌';
      const label = v.status === 'implemented' ? '구현됨' : v.status === 'partial' ? '부분적' : '서버 구현 필요';
      lines.push(`- ${icon} [${label}] ${v.claim}`);
    }
    lines.push('');
    lines.push('### 코드');
    lines.push('');
    lines.push('```' + input.language);
    lines.push(bestTemplate.code);
    lines.push('```');

    if (input.vulnerable_code) {
      lines.push('');
      lines.push('### 원본 코드 대비 보안 개선사항');
      for (const v of validated) {
        const icon = v.status === 'implemented' ? '✅' : v.status === 'partial' ? '⚠️' : '❌';
        lines.push(`- ${icon} ${v.claim}`);
      }
    }
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
  };
}
