import type { SecurityRule } from '../types/index.js';

export const authRules: SecurityRule[] = [
  {
    id: 'SCG-AUF-SECRET-001',
    title: 'Hardcoded Password / Secret',
    titleKo: '하드코딩된 비밀번호/시크릿',
    severity: 'critical',
    confidence: 'high',
    category: 'A07:2021-Identification and Authentication Failures',
    cweId: 'CWE-798',
    owaspCategory: 'A07',
    description: 'Passwords or secrets are hardcoded in source code instead of environment variables.',
    descriptionKo: '비밀번호나 시크릿이 환경변수 대신 소스코드에 하드코딩되어 있습니다.',
    patterns: [
      {
        regex: /(?:password|passwd|pwd|secret|apiKey|api_key|apiSecret|api_secret|accessToken|access_token|privateKey|private_key)\s*[:=]\s*['"][^'"]{4,}['"]/i,
        negativeRegex: /(?:process\.env|os\.environ|getenv|config\.|placeholder|example|changeme|xxx|your_|<.*>|\*{3,})/i,
      },
      {
        regex: /(?:PRIVATE.KEY|SECRET.KEY|JWT.SECRET|DB.PASSWORD|DATABASE.PASSWORD)\s*[:=]\s*['"][^'"]{4,}['"]/i,
        negativeRegex: /process\.env|os\.environ|getenv/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Store secrets in environment variables or a secure vault. Never commit secrets to source code.',
      descriptionKo: '시크릿은 환경변수나 보안 볼트에 저장하세요. 소스코드에 시크릿을 절대 커밋하지 마세요.',
      secureExample: `// ✅ Secure: Use environment variables
const dbPassword = process.env.DB_PASSWORD;
const jwtSecret = process.env.JWT_SECRET;

// ✅ Secure: Use a secrets manager
const secret = await secretManager.getSecret('my-api-key');`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
      ],
    },
    tags: ['hardcoded-secret', 'credentials', 'authentication'],
  },

  {
    id: 'SCG-AUF-SECRET-002',
    title: 'Hardcoded API Key Pattern',
    titleKo: 'API 키 패턴 하드코딩',
    severity: 'critical',
    confidence: 'high',
    category: 'A07:2021-Identification and Authentication Failures',
    cweId: 'CWE-798',
    owaspCategory: 'A07',
    description: 'API keys for known services detected in source code.',
    descriptionKo: '알려진 서비스의 API 키가 소스코드에서 감지되었습니다.',
    patterns: [
      { regex: /AKIA[0-9A-Z]{16}/ },
      { regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/ },
      { regex: /sk-[A-Za-z0-9]{32,}/ },
      { regex: /sk_(?:live|test)_[A-Za-z0-9]{24,}/ },
      { regex: /xox[bporas]-[A-Za-z0-9-]{10,}/ },
      { regex: /-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----/ },
      { regex: /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_.]{10,}/ },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Remove API keys from source code immediately. Rotate compromised keys. Use environment variables.',
      descriptionKo: '소스코드에서 API 키를 즉시 제거하세요. 노출된 키를 교체하세요. 환경변수를 사용하세요.',
      secureExample: `// ✅ Secure: Use environment variables
const apiKey = process.env.OPENAI_API_KEY;`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
      ],
    },
    tags: ['api-key', 'aws', 'github', 'openai', 'stripe', 'slack', 'jwt'],
  },

  {
    id: 'SCG-AUF-HASH-001',
    title: 'Weak Password Hashing (MD5/SHA1)',
    titleKo: '취약한 비밀번호 해싱 (MD5/SHA1)',
    severity: 'high',
    confidence: 'high',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-328',
    owaspCategory: 'A02',
    description: 'MD5 or SHA1 is used for password hashing. These are fast hashes, vulnerable to brute force.',
    descriptionKo: '비밀번호 해싱에 MD5 또는 SHA1이 사용됩니다. 빠른 해시 함수로 무차별 대입 공격에 취약합니다.',
    patterns: [
      {
        regex: /(?:createHash|hashlib\.md5|hashlib\.sha1|MessageDigest\.getInstance)\s*\(\s*['"](?:md5|sha1)['"]/i,
      },
      {
        regex: /(?:md5|sha1)\s*\(.*?(?:password|passwd|pwd)/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Use bcrypt, scrypt, or Argon2 for password hashing. Never use MD5/SHA1 for passwords.',
      descriptionKo: '비밀번호 해싱에 bcrypt, scrypt, 또는 Argon2를 사용하세요. MD5/SHA1은 절대 사용하지 마세요.',
      secureExample: `// ✅ Secure: Use bcrypt
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
      ],
    },
    tags: ['password', 'hashing', 'md5', 'sha1', 'cryptography'],
  },

  {
    id: 'SCG-AUF-JWT-001',
    title: 'JWT Without Verification',
    titleKo: '검증 없는 JWT 사용',
    severity: 'critical',
    confidence: 'high',
    category: 'A07:2021-Identification and Authentication Failures',
    cweId: 'CWE-345',
    owaspCategory: 'A07',
    description: 'JWT token is decoded without signature verification.',
    descriptionKo: 'JWT 토큰이 서명 검증 없이 디코딩됩니다.',
    patterns: [
      {
        regex: /jwt\.decode\s*\(/,
        negativeRegex: /jwt\.verify/,
      },
      {
        regex: /jsonwebtoken.*?\.decode\s*\(/,
        negativeRegex: /\.verify\s*\(/,
      },
      {
        regex: /algorithms\s*[:=]\s*\[?\s*['"]none['"]/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Always use jwt.verify() with a strong secret. Never accept "none" algorithm.',
      descriptionKo: '항상 jwt.verify()를 강력한 시크릿과 함께 사용하세요. "none" 알고리즘을 허용하지 마세요.',
      secureExample: `// ✅ Secure: Verify JWT with algorithm restriction
import jwt from 'jsonwebtoken';
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
      ],
    },
    tags: ['jwt', 'authentication', 'token'],
  },

  {
    id: 'SCG-AUF-COOKIE-001',
    title: 'Insecure Cookie Configuration',
    titleKo: '안전하지 않은 쿠키 설정',
    severity: 'medium',
    confidence: 'high',
    category: 'A07:2021-Identification and Authentication Failures',
    cweId: 'CWE-614',
    owaspCategory: 'A07',
    description: 'Session cookies are missing security flags (httpOnly, secure, sameSite).',
    descriptionKo: '세션 쿠키에 보안 플래그(httpOnly, secure, sameSite)가 누락되어 있습니다.',
    patterns: [
      {
        regex: /(?:cookie|session)\s*(?:=|\()\s*\{[^}]*(?:httpOnly\s*:\s*false|secure\s*:\s*false)/i,
      },
      {
        regex: /res\.cookie\s*\([^)]*(?!httpOnly)/i,
        negativeRegex: /httpOnly\s*:\s*true/i,
      },
      {
        regex: /Set-Cookie.*?(?!HttpOnly|Secure|SameSite)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Set httpOnly, secure, and sameSite flags on all session cookies.',
      descriptionKo: '모든 세션 쿠키에 httpOnly, secure, sameSite 플래그를 설정하세요.',
      secureExample: `// ✅ Secure: Proper cookie configuration
res.cookie('sessionId', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000,
  path: '/',
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      ],
    },
    tags: ['cookie', 'session', 'httpOnly', 'secure'],
  },

  {
    id: 'SCG-AUF-CORS-001',
    title: 'Permissive CORS Configuration',
    titleKo: '허용적인 CORS 설정',
    severity: 'high',
    confidence: 'high',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-942',
    owaspCategory: 'A05',
    description: 'CORS is configured with wildcard (*) origin, allowing any domain to make requests.',
    descriptionKo: 'CORS가 와일드카드(*) 오리진으로 설정되어 모든 도메인에서 요청할 수 있습니다.',
    patterns: [
      {
        regex: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"]\*['"]/i,
      },
      {
        regex: /cors\s*\(\s*\)/,
      },
      {
        regex: /cors\s*\(\s*\{\s*origin\s*:\s*true\s*\}/,
      },
      {
        regex: /(?:Access-Control-Allow-Credentials|credentials)\s*[:=]\s*(?:true|['"]true['"]).{0,200}?origin\s*[:=]\s*['"]\*/is,
        multiline: true,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Restrict CORS to specific trusted origins. Never use wildcard with credentials.',
      descriptionKo: 'CORS를 신뢰할 수 있는 특정 오리진으로 제한하세요. credentials와 함께 와일드카드를 사용하지 마세요.',
      secureExample: `// ✅ Secure: Restrict CORS origins
app.use(cors({
  origin: ['https://app.example.com', 'https://admin.example.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['cors', 'access-control', 'misconfiguration'],
  },

  {
    id: 'SCG-AUF-CSRF-001',
    title: 'Missing CSRF Protection',
    titleKo: 'CSRF 보호 미적용',
    severity: 'high',
    confidence: 'medium',
    category: 'A01:2021-Broken Access Control',
    cweId: 'CWE-352',
    owaspCategory: 'A01',
    description: 'State-changing endpoints lack CSRF protection tokens.',
    descriptionKo: '상태 변경 엔드포인트에 CSRF 보호 토큰이 적용되지 않았습니다.',
    patterns: [
      {
        regex: /app\.(?:post|put|patch|delete)\s*\(/,
        negativeRegex: /(?:csrf|csurf|csrfProtection|_csrf|xsrf|XSRF)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Implement CSRF tokens for all state-changing requests. Use SameSite cookies as defense-in-depth.',
      descriptionKo: '모든 상태 변경 요청에 CSRF 토큰을 구현하세요. SameSite 쿠키를 추가 방어로 사용하세요.',
      secureExample: `// ✅ Secure: CSRF protection with csurf
import csrf from 'csurf';
const csrfProtection = csrf({ cookie: { sameSite: 'strict' } });
app.post('/transfer', csrfProtection, (req, res) => { ... });`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['csrf', 'access-control'],
  },

  {
    id: 'SCG-AUF-CSRF-002',
    title: 'Empty CSRF Token Value',
    titleKo: 'CSRF 토큰 빈 값',
    severity: 'high',
    confidence: 'high',
    category: 'A01:2021-Broken Access Control',
    cweId: 'CWE-352',
    owaspCategory: 'A01',
    description: 'CSRF token field has an empty value. Tokens must be dynamically generated by the server.',
    descriptionKo: 'CSRF 토큰 필드의 값이 비어 있습니다. 토큰은 서버에서 동적으로 생성해야 합니다.',
    patterns: [
      {
        regex: /name\s*=\s*["']_csrf["'][^>]*value\s*=\s*["']\s*["']/i,
      },
      {
        regex: /value\s*=\s*["']\s*["'][^>]*name\s*=\s*["']_csrf["']/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Generate CSRF tokens server-side and inject them into forms dynamically. Never use empty token values.',
      descriptionKo: 'CSRF 토큰을 서버에서 생성하고 폼에 동적으로 주입하세요. 빈 토큰 값을 사용하지 마세요.',
      secureExample: `// ✅ 서버: CSRF 토큰 발급 엔드포인트
import crypto from 'crypto';
app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  res.json({ token });
});

// ✅ 클라이언트: 페이지 로드 시 토큰 획득
async function fetchCsrfToken() {
  const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
  const { token } = await res.json();
  document.getElementById('csrfToken').value = token;
}
window.addEventListener('DOMContentLoaded', fetchCsrfToken);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['csrf', 'token', 'empty-value'],
  },

  {
    id: 'SCG-AUF-OAUTH-001',
    title: 'OAuth Callback Missing State Validation',
    titleKo: 'OAuth 콜백에서 state 파라미터 검증 누락',
    severity: 'high',
    confidence: 'medium',
    category: 'A07:2021-Identification and Authentication Failures',
    cweId: 'CWE-352',
    owaspCategory: 'A07',
    description: 'OAuth callback endpoint does not validate the state parameter, making it vulnerable to CSRF attacks on the OAuth flow.',
    descriptionKo: 'OAuth 콜백 엔드포인트에서 state 파라미터를 검증하지 않아 OAuth 플로우가 CSRF 공격에 취약합니다.',
    patterns: [
      {
        regex: /(?:\/callback|\/oauth\/callback|\/auth\/callback).*(?:code|authorization_code)/i,
        negativeRegex: /state\s*(?:===|!==|==|!=)|verifyState|validateState|req\.session\.state/i,
      },
      {
        regex: /oauth.*callback.*(?:req\.query\.code|params\.code)/i,
        negativeRegex: /state/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Always validate the OAuth state parameter in callback endpoints by comparing it with the session-stored value.',
      descriptionKo: 'OAuth 콜백 엔드포인트에서 반드시 state 파라미터를 세션에 저장된 값과 비교 검증하세요.',
      secureExample: `// ✅ Secure: OAuth 콜백에서 state 검증
app.get('/auth/callback', (req, res) => {
  const { code, state } = req.query;
  if (!state || state !== req.session.oauthState) {
    return res.status(403).json({ error: 'Invalid OAuth state' });
  }
  delete req.session.oauthState;
  // ... exchange code for token
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#oauth',
      ],
    },
    tags: ['oauth', 'csrf', 'state', 'callback'],
  },

  {
    id: 'SCG-AUF-SESSION-001',
    title: 'Insecure Session Configuration',
    titleKo: '안전하지 않은 세션 설정',
    severity: 'medium',
    confidence: 'medium',
    category: 'A07:2021-Identification and Authentication Failures',
    cweId: 'CWE-384',
    owaspCategory: 'A07',
    description: 'Session middleware is configured without secure options.',
    descriptionKo: '세션 미들웨어가 보안 옵션 없이 설정되어 있습니다.',
    patterns: [
      {
        regex: /session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]{1,10}['"]/i,
      },
      {
        regex: /session\s*\(\s*\{[^}]*resave\s*:\s*true/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Use strong session secrets from env vars. Set secure cookie options.',
      descriptionKo: '환경변수의 강력한 세션 시크릿을 사용하세요. 보안 쿠키 옵션을 설정하세요.',
      secureExample: `// ✅ Secure: Proper session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict', maxAge: 3600000 },
}));`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      ],
    },
    tags: ['session', 'authentication', 'cookie'],
  },
];
