import type { SecurityRule } from '../types/index.js';

export const configRules: SecurityRule[] = [
  {
    id: 'SCG-MCF-DEBUG-001',
    title: 'Debug Mode Enabled',
    titleKo: '디버그 모드 활성화',
    severity: 'medium',
    confidence: 'high',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-489',
    owaspCategory: 'A05',
    description: 'Debug mode is enabled, potentially exposing sensitive information.',
    descriptionKo: '디버그 모드가 활성화되어 민감한 정보가 노출될 수 있습니다.',
    patterns: [
      {
        regex: /(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|['"]true['"])/i,
        negativeRegex: /(?:process\.env|os\.environ|NODE_ENV.*production)/i,
      },
      {
        regex: /app\.(?:debug|DEBUG)\s*=\s*True/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Disable debug mode in production. Use environment variables to control debug settings.',
      descriptionKo: '프로덕션에서 디버그 모드를 비활성화하세요. 환경변수로 디버그 설정을 제어하세요.',
      secureExample: `// ✅ Secure: Environment-based debug
const isDebug = process.env.NODE_ENV !== 'production';`,
      references: ['https://cwe.mitre.org/data/definitions/489.html'],
    },
    tags: ['debug', 'misconfiguration', 'information-disclosure'],
  },

  {
    id: 'SCG-MCF-ERR-001',
    title: 'Verbose Error Messages / Stack Traces Exposed',
    titleKo: '상세한 에러 메시지 / 스택 트레이스 노출',
    severity: 'medium',
    confidence: 'medium',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-209',
    owaspCategory: 'A05',
    description: 'Detailed error messages or stack traces are sent to the client, exposing internal details.',
    descriptionKo: '상세한 에러 메시지나 스택 트레이스가 클라이언트에 전송되어 내부 정보가 노출됩니다.',
    patterns: [
      {
        regex: /res\.(?:json|send|status)\s*\(.*?(?:err\.stack|error\.stack|err\.message|error\.message)/i,
      },
      {
        regex: /\.catch\s*\(.*?res\..*?(?:err|error)\s*\)/i,
      },
      {
        regex: /(?:res\.status\(\d+\)|res\.json)\s*\(\s*\{\s*(?:error|message)\s*:\s*(?:err|error|e)\b/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Return generic error messages to clients. Log detailed errors server-side only.',
      descriptionKo: '클라이언트에는 일반적인 에러 메시지를 반환하세요. 상세 에러는 서버 측에서만 로깅하세요.',
      secureExample: `// ✅ Secure: Generic error response + server logging
app.use((err, req, res, next) => {
  logger.error(err.stack);  // Log full details server-side
  res.status(500).json({ error: 'Internal server error' });  // Generic to client
});`,
      references: ['https://cwe.mitre.org/data/definitions/209.html'],
    },
    tags: ['error-handling', 'information-disclosure', 'stack-trace'],
  },

  {
    id: 'SCG-MCF-HELMET-001',
    title: 'Missing Security Headers Middleware',
    titleKo: '보안 헤더 미들웨어 미사용',
    severity: 'medium',
    confidence: 'low',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-693',
    owaspCategory: 'A05',
    description: 'Express app does not use helmet or set security headers.',
    descriptionKo: 'Express 앱이 helmet을 사용하지 않거나 보안 헤더를 설정하지 않습니다.',
    patterns: [
      {
        regex: /express\s*\(\s*\)/,
        negativeRegex: /helmet|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Use helmet middleware or manually set security headers.',
      descriptionKo: 'helmet 미들웨어를 사용하거나 수동으로 보안 헤더를 설정하세요.',
      secureExample: `// ✅ Secure: Use helmet
import helmet from 'helmet';
app.use(helmet());`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      ],
    },
    tags: ['headers', 'helmet', 'express', 'misconfiguration'],
  },

  {
    id: 'SCG-MCF-RATE-001',
    title: 'Missing Rate Limiting',
    titleKo: '속도 제한(Rate Limiting) 미적용',
    severity: 'medium',
    confidence: 'low',
    category: 'A04:2021-Insecure Design',
    cweId: 'CWE-770',
    owaspCategory: 'A04',
    description: 'API endpoints lack server-side rate limiting, vulnerable to brute force and DoS attacks. Client-side rate limiting alone is insufficient as it can be easily bypassed.',
    descriptionKo: 'API 엔드포인트에 서버측 속도 제한이 없어 무차별 대입 공격과 DoS 공격에 취약합니다. 클라이언트측 rate limiting만으로는 우회 가능하므로 서버측 구현이 필수입니다.',
    patterns: [
      {
        regex: /app\.(?:post|put)\s*\(\s*['"]\/(?:login|auth|signin|register|signup|reset|forgot|api)/i,
        negativeRegex: /(?:rateLimit|rateLimiter|throttle|limiter|slowDown)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Implement rate limiting on authentication and sensitive endpoints.',
      descriptionKo: '인증 및 민감한 엔드포인트에 속도 제한을 구현하세요.',
      secureExample: `// ✅ Secure: Rate limiting with express-rate-limit
import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many login attempts, please try again later.',
});
app.post('/login', loginLimiter, loginHandler);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
      ],
    },
    tags: ['rate-limiting', 'brute-force', 'dos'],
  },

  {
    id: 'SCG-MCF-DIR-001',
    title: 'Directory Listing / Static File Exposure',
    titleKo: '디렉토리 리스팅 / 정적 파일 노출',
    severity: 'medium',
    confidence: 'medium',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-548',
    owaspCategory: 'A05',
    description: 'Static file serving may expose directory listings or sensitive files.',
    descriptionKo: '정적 파일 서빙이 디렉토리 리스팅이나 민감한 파일을 노출할 수 있습니다.',
    patterns: [
      {
        regex: /express\.static\s*\(\s*['"]\.\/?['"]\s*\)/i,
      },
      {
        regex: /serveStatic\s*\(\s*['"]\/['"]\s*\)/i,
      },
      {
        regex: /directory\s*:\s*true|listing\s*:\s*true/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Serve static files from a specific directory. Disable directory listing.',
      descriptionKo: '특정 디렉토리에서 정적 파일을 제공하세요. 디렉토리 리스팅을 비활성화하세요.',
      secureExample: `// ✅ Secure: Specific directory with dotfiles denied
app.use('/static', express.static('public', {
  dotfiles: 'deny',
  index: false,
}));`,
      references: ['https://cwe.mitre.org/data/definitions/548.html'],
    },
    tags: ['directory-listing', 'static-files', 'misconfiguration'],
  },

  {
    id: 'SCG-MCF-ENV-001',
    title: 'Sensitive Data in .env Committed',
    titleKo: '.env 파일의 민감정보 커밋',
    severity: 'high',
    confidence: 'high',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-312',
    owaspCategory: 'A05',
    description: '.env file contains sensitive values and may be committed to version control.',
    descriptionKo: '.env 파일에 민감한 값이 포함되어 있으며 버전 관리에 커밋될 수 있습니다.',
    patterns: [
      {
        regex: /(?:DB_PASSWORD|DATABASE_PASSWORD|SECRET_KEY|PRIVATE_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*[^\s$]{4,}/i,
        negativeRegex: /\$\{|changeme|your_|<.*>|example|placeholder/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Add .env to .gitignore. Use .env.example with placeholder values for documentation.',
      descriptionKo: '.gitignore에 .env를 추가하세요. 문서화를 위해 .env.example에 플레이스홀더 값을 사용하세요.',
      secureExample: `# .env.example (commit this, not .env)
DB_PASSWORD=<your-database-password>
JWT_SECRET=<generate-strong-secret>
API_KEY=<your-api-key>`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
      ],
    },
    tags: ['env', 'secrets', 'git', 'misconfiguration'],
  },

  {
    id: 'SCG-LOG-SENS-001',
    title: 'Sensitive Data in Logs',
    titleKo: '로그에 민감정보 포함',
    severity: 'medium',
    confidence: 'medium',
    category: 'A09:2021-Security Logging and Monitoring Failures',
    cweId: 'CWE-532',
    owaspCategory: 'A09',
    description: 'Sensitive data (passwords, tokens, credit cards) may be logged.',
    descriptionKo: '민감정보(비밀번호, 토큰, 신용카드)가 로그에 기록될 수 있습니다.',
    patterns: [
      {
        regex: /(?:console\.log|logger\.(?:info|debug|warn|error))\s*\(.*?(?:password|passwd|pwd|token|secret|credit.?card|ssn|social.?security)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Never log sensitive data. Mask or redact sensitive fields before logging.',
      descriptionKo: '민감정보를 절대 로그에 기록하지 마세요. 로깅 전 민감 필드를 마스킹하세요.',
      secureExample: `// ✅ Secure: Mask sensitive fields
const safeLog = { ...user, password: '***', token: '***' };
logger.info('User login', safeLog);`,
      references: ['https://cwe.mitre.org/data/definitions/532.html'],
    },
    tags: ['logging', 'sensitive-data', 'pii'],
  },

  {
    id: 'SCG-MCF-HTTP-001',
    title: 'HTTP Used Instead of HTTPS',
    titleKo: 'HTTPS 대신 HTTP 사용',
    severity: 'medium',
    confidence: 'low',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-319',
    owaspCategory: 'A02',
    description: 'HTTP URLs detected for API calls or resource loading that should use HTTPS.',
    descriptionKo: 'HTTPS를 사용해야 하는 API 호출이나 리소스 로딩에 HTTP URL이 감지되었습니다.',
    patterns: [
      {
        regex: /(?:fetch|axios|request|http\.get)\s*\(\s*['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
      },
      {
        regex: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]*api[^'"]*['"]/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Use HTTPS for all external communications. Redirect HTTP to HTTPS.',
      descriptionKo: '모든 외부 통신에 HTTPS를 사용하세요. HTTP를 HTTPS로 리다이렉트하세요.',
      secureExample: `// ✅ Secure: Use HTTPS
const response = await fetch('https://api.example.com/data');`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
      ],
    },
    tags: ['http', 'https', 'transport-security'],
  },
];
