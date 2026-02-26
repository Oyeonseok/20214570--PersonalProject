export interface SecurePattern {
  category: string;
  categoryKo: string;
  language: string;
  patterns: {
    name: string;
    nameKo: string;
    description: string;
    code: string;
  }[];
}

export const SECURE_PATTERNS: SecurePattern[] = [
  {
    category: 'input-validation',
    categoryKo: '입력 검증',
    language: 'typescript',
    patterns: [
      {
        name: 'Zod Schema Validation',
        nameKo: 'Zod 스키마 검증',
        description: 'Type-safe input validation with Zod',
        code: `import { z } from 'zod';

const userSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100).regex(/^[a-zA-Z가-힣\\s]+$/),
  age: z.number().int().min(0).max(150).optional(),
});

// Express middleware
function validate(schema: z.ZodSchema) {
  return (req, res, next) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (err) {
      res.status(400).json({ error: 'Invalid input' });
    }
  };
}`,
      },
    ],
  },
  {
    category: 'authentication',
    categoryKo: '인증',
    language: 'typescript',
    patterns: [
      {
        name: 'Bcrypt Password Hashing',
        nameKo: 'Bcrypt 비밀번호 해싱',
        description: 'Secure password storage with bcrypt',
        code: `import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}`,
      },
    ],
  },
  {
    category: 'output-encoding',
    categoryKo: '출력 인코딩',
    language: 'typescript',
    patterns: [
      {
        name: 'HTML Entity Encoding',
        nameKo: 'HTML 엔티티 인코딩',
        description: 'Prevent XSS by encoding HTML output',
        code: `function escapeHtml(str: string): string {
  const map: Record<string, string> = {
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#x27;', '/': '&#x2F;',
  };
  return str.replace(/[&<>"'/]/g, (c) => map[c]);
}`,
      },
    ],
  },
  {
    category: 'csrf-protection',
    categoryKo: 'CSRF 방어',
    language: 'typescript',
    patterns: [
      {
        name: 'Double Submit Cookie',
        nameKo: '이중 제출 쿠키',
        description: 'CSRF protection using double submit cookie pattern',
        code: `import crypto from 'crypto';

function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function csrfMiddleware(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    const token = generateCsrfToken();
    res.cookie('csrf-token', token, { sameSite: 'strict' });
    req.csrfToken = token;
    return next();
  }
  const cookieToken = req.cookies['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];
  if (!cookieToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}`,
      },
    ],
  },
  {
    category: 'error-handling',
    categoryKo: '에러 처리',
    language: 'typescript',
    patterns: [
      {
        name: 'Secure Error Handler',
        nameKo: '보안 에러 핸들러',
        description: 'Error handling without information disclosure',
        code: `function errorHandler(err: Error, req, res, _next) {
  const requestId = crypto.randomUUID();
  logger.error({ requestId, error: err.message, stack: err.stack });
  
  const statusCode = 'statusCode' in err ? (err as any).statusCode : 500;
  res.status(statusCode).json({
    error: statusCode === 500 ? 'Internal server error' : err.message,
    requestId,
  });
}`,
      },
    ],
  },
  {
    category: 'server-security-middleware',
    categoryKo: '서버 보안 미들웨어',
    language: 'typescript',
    patterns: [
      {
        name: 'Express Security Hardening',
        nameKo: 'Express 보안 강화 설정',
        description: 'helmet, rate-limit, CORS, trust proxy, body size limit',
        code: `import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(','), credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(rateLimit({ windowMs: 60_000, max: 100 }));`,
      },
    ],
  },
  {
    category: 'jwt-authentication',
    categoryKo: 'JWT 인증',
    language: 'typescript',
    patterns: [
      {
        name: 'Secure JWT Verify',
        nameKo: '안전한 JWT 검증',
        description: 'JWT verification with algorithm pinning and proper error handling',
        code: `import jwt from 'jsonwebtoken';

function verifyToken(token: string): jwt.JwtPayload {
  return jwt.verify(token, process.env.JWT_SECRET!, {
    algorithms: ['HS256'],
    issuer: 'my-app',
    maxAge: '1h',
  }) as jwt.JwtPayload;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = verifyToken(header.slice(7));
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}`,
      },
    ],
  },
  {
    category: 'file-upload-security',
    categoryKo: '파일 업로드 보안',
    language: 'typescript',
    patterns: [
      {
        name: 'Secure File Upload with multer',
        nameKo: 'multer를 사용한 안전한 파일 업로드',
        description: 'File upload with type/size validation, random filename, and safe storage',
        code: `import multer from 'multer';
import crypto from 'crypto';
import path from 'path';

const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
const MAX_SIZE = 5 * 1024 * 1024;

const upload = multer({
  limits: { fileSize: MAX_SIZE },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME.includes(file.mimetype)) return cb(new Error('Invalid file type'));
    cb(null, true);
  },
  storage: multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) =>
      cb(null, crypto.randomUUID() + path.extname(file.originalname)),
  }),
});

app.post('/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ filename: req.file.filename });
});`,
      },
    ],
  },
  {
    category: 'ssrf-prevention',
    categoryKo: 'SSRF 방지',
    language: 'typescript',
    patterns: [
      {
        name: 'URL Validation for Server-Side Requests',
        nameKo: '서버 사이드 요청용 URL 검증',
        description: 'Block internal IPs, cloud metadata, and non-HTTP protocols',
        code: `function isAllowedUrl(input: string): URL {
  const url = new URL(input);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Invalid protocol');
  const hostname = url.hostname;
  const blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '169.254.169.254',
                   'metadata.google.internal', '100.100.100.200'];
  if (blocked.includes(hostname)) throw new Error('Blocked host');
  if (/^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|::1|fe80::)/.test(hostname))
    throw new Error('Blocked internal IP');
  return url;
}

async function secureFetch(userUrl: string) {
  const validated = isAllowedUrl(userUrl);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);
  return fetch(validated.toString(), { signal: controller.signal, redirect: 'error' });
}`,
      },
    ],
  },
  {
    category: 'prototype-pollution-prevention',
    categoryKo: '프로토타입 오염 방지',
    language: 'typescript',
    patterns: [
      {
        name: 'Safe Object Merge',
        nameKo: '안전한 객체 병합',
        description: 'Merge objects without prototype pollution risk',
        code: `function safeMerge<T extends Record<string, unknown>>(target: T, source: unknown): T {
  if (!source || typeof source !== 'object') return target;
  for (const key of Object.keys(source as object)) {
    if (['__proto__', 'constructor', 'prototype'].includes(key)) continue;
    (target as any)[key] = (source as any)[key];
  }
  return target;
}

// Or use schema validation
import { z } from 'zod';
const schema = z.object({ name: z.string(), value: z.number() }).strict();
const safe = schema.parse(req.body);`,
      },
    ],
  },
  {
    category: 'idor-prevention',
    categoryKo: 'IDOR 방지',
    language: 'typescript',
    patterns: [
      {
        name: 'Resource Ownership Verification',
        nameKo: '리소스 소유권 확인',
        description: 'Always verify resource ownership to prevent IDOR',
        code: `app.get('/posts/:id', authMiddleware, async (req, res) => {
  const post = await db.query(
    'SELECT * FROM posts WHERE id = $1 AND author_id = $2',
    [req.params.id, req.user.id]
  );
  if (!post.rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(post.rows[0]);
});

app.delete('/posts/:id', authMiddleware, async (req, res) => {
  const result = await db.query(
    'DELETE FROM posts WHERE id = $1 AND author_id = $2 RETURNING id',
    [req.params.id, req.user.id]
  );
  if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ deleted: true });
});`,
      },
    ],
  },
];

export function getSecurePatternsResource(language?: string, category?: string): string {
  let filtered = SECURE_PATTERNS;
  if (language) filtered = filtered.filter((p) => p.language === language);
  if (category) filtered = filtered.filter((p) => p.category === category);

  const lines: string[] = [];
  lines.push('# 시큐어코딩 패턴 사전');
  lines.push('');

  for (const group of filtered) {
    lines.push(`## ${group.categoryKo} (${group.category}) - ${group.language}`);
    lines.push('');
    for (const pattern of group.patterns) {
      lines.push(`### ${pattern.nameKo}`);
      lines.push(pattern.description);
      lines.push('');
      lines.push('```' + group.language);
      lines.push(pattern.code);
      lines.push('```');
      lines.push('');
    }
  }

  return lines.join('\n');
}
