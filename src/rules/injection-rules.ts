import type { SecurityRule } from '../types/index.js';

export const injectionRules: SecurityRule[] = [
  {
    id: 'SCG-INJ-SQL-001',
    title: 'SQL Injection via String Concatenation',
    titleKo: '문자열 결합을 통한 SQL 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-89',
    owaspCategory: 'A03',
    description: 'User input is directly concatenated into SQL query string, allowing SQL injection attacks.',
    descriptionKo: '사용자 입력이 SQL 쿼리 문자열에 직접 결합되어 SQL 인젝션 공격에 노출됩니다.',
    patterns: [
      {
        regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\s.*?\+\s*(?:req\.|request\.|params|query|body|args|form|input|user)/i,
        negativeRegex: /(?:\.escape\(|\.sanitize\(|parameterized|prepared)/i,
      },
      {
        regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\s.*?\$\{.*?(?:req|request|params|query|body|args|form|input|user)/i,
        negativeRegex: /(?:\.escape\(|\.sanitize\()/i,
      },
      {
        regex: /(?:query|execute|exec)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE).*?\+/i,
        negativeRegex: /(?:prepare|parameterize)/i,
      },
      {
        regex: /f"(?:SELECT|INSERT|UPDATE|DELETE)\s.*?\{.*?\}"/i,
      },
      {
        regex: /f'(?:SELECT|INSERT|UPDATE|DELETE)\s.*?\{.*?\}'/i,
      },
      {
        regex: /(?:cursor|conn|connection|db)\.execute\(\s*f?["'].*?%s.*?["']\s*%/i,
        negativeRegex: /\.execute\(\s*["'][^"']*%s[^"']*["']\s*,\s*\(/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Use parameterized queries (prepared statements) instead of string concatenation.',
      descriptionKo: '문자열 결합 대신 파라미터화된 쿼리(Prepared Statement)를 사용하세요.',
      secureExample: `// ✅ Secure: Parameterized query
const result = await db.query(
  'SELECT * FROM users WHERE id = $1 AND email = $2',
  [userId, email]
);

# ✅ Python: Parameterized query
cursor.execute(
    "SELECT * FROM users WHERE id = %s",
    (user_id,)
)`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/89.html',
      ],
    },
    tags: ['sql', 'injection', 'database', 'owasp-top10', 'critical'],
  },

  {
    id: 'SCG-INJ-NOS-001',
    title: 'NoSQL Injection',
    titleKo: 'NoSQL 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-943',
    owaspCategory: 'A03',
    description: 'User input is passed directly to NoSQL query operators, allowing NoSQL injection.',
    descriptionKo: '사용자 입력이 NoSQL 쿼리 연산자에 직접 전달되어 NoSQL 인젝션 공격에 노출됩니다.',
    patterns: [
      {
        regex: /\.find\(\s*\{[^}]*(?:req\.|request\.)/i,
      },
      {
        regex: /\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists).*?(?:req\.|request\.|body|query|params)/i,
      },
      {
        regex: /\.find(?:One)?\(\s*(?:req\.body|req\.query|req\.params)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express', 'fastify'],
    remediation: {
      description: 'Validate and sanitize input before using in NoSQL queries. Use explicit field matching.',
      descriptionKo: 'NoSQL 쿼리에 사용하기 전 입력값을 검증하고 새니타이즈하세요.',
      secureExample: `// ✅ Secure: Explicit field validation
const email = String(req.body.email);  // Force string type
const user = await User.findOne({ email });`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['nosql', 'mongodb', 'injection'],
  },

  {
    id: 'SCG-INJ-CMD-001',
    title: 'OS Command Injection',
    titleKo: 'OS 명령어 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-78',
    owaspCategory: 'A03',
    description: 'User input is passed to system command execution functions, allowing command injection.',
    descriptionKo: '사용자 입력이 시스템 명령어 실행 함수에 전달되어 명령어 인젝션 공격에 노출됩니다.',
    patterns: [
      {
        regex: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\(.*?(?:req\.|request\.|params|query|body|input|user)/i,
        negativeRegex: /execFile\s*\(\s*['"][^'"]+['"]\s*,\s*\[/i,
      },
      {
        regex: /child_process.*?(?:exec|spawn)\s*\(.*?\$\{/i,
      },
      {
        regex: /(?:exec|execSync)\s*\(\s*`[^`]*\$\{/i,
      },
      {
        regex: /os\.(?:system|popen)\s*\(.*?(?:request|input|args)/i,
      },
      {
        regex: /subprocess\.(?:call|run|Popen)\s*\(.*?(?:request|input|args)/i,
        negativeRegex: /subprocess\.(?:call|run|Popen)\s*\(\s*\[/i,
      },
      {
        regex: /Runtime\.getRuntime\(\)\.exec\s*\(.*?\+/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Avoid passing user input to command execution. Use parameterized APIs or allowlists.',
      descriptionKo: '사용자 입력을 명령어 실행에 전달하지 마세요. 파라미터화된 API 또는 허용 목록을 사용하세요.',
      secureExample: `// ✅ Secure: Use execFile with argument array (no shell interpolation)
import { execFile } from 'child_process';
execFile('/usr/bin/convert', [inputFile, outputFile], callback);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/78.html',
      ],
    },
    tags: ['command-injection', 'rce', 'os'],
  },

  {
    id: 'SCG-INJ-CODE-001',
    title: 'Code Injection via eval()',
    titleKo: 'eval()을 통한 코드 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-94',
    owaspCategory: 'A03',
    description: 'Use of eval() with dynamic input enables arbitrary code execution.',
    descriptionKo: '동적 입력과 함께 eval()을 사용하면 임의 코드 실행이 가능합니다.',
    patterns: [
      {
        regex: /\beval\s*\(/,
        negativeRegex: /\/\/.*eval|\/\*.*eval/,
      },
      {
        regex: /new\s+Function\s*\(/,
      },
      {
        regex: /setTimeout\s*\(\s*['"`]/,
      },
      {
        regex: /setInterval\s*\(\s*['"`]/,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Never use eval() with user input. Use JSON.parse() for data, or safe alternatives.',
      descriptionKo: '사용자 입력에 eval()을 절대 사용하지 마세요. 데이터는 JSON.parse()를 사용하세요.',
      secureExample: `// ✅ Secure: Use JSON.parse instead of eval
const data = JSON.parse(userInput);

// ✅ Secure: Use a safe expression parser
import { evaluate } from 'mathjs';
const result = evaluate(expression);`,
      references: [
        'https://cwe.mitre.org/data/definitions/94.html',
      ],
    },
    tags: ['eval', 'code-injection', 'rce'],
  },

  {
    id: 'SCG-INJ-PATH-001',
    title: 'Path Traversal',
    titleKo: '경로 탐색 (디렉토리 트래버설)',
    severity: 'high',
    confidence: 'high',
    category: 'A01:2021-Broken Access Control',
    cweId: 'CWE-22',
    owaspCategory: 'A01',
    description: 'User input is used in file path construction without validation, allowing path traversal.',
    descriptionKo: '사용자 입력이 검증 없이 파일 경로 구성에 사용되어 경로 탐색 공격에 노출됩니다.',
    patterns: [
      {
        regex: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|access)\s*\(.*?(?:req\.|request\.|params|query|body)/i,
        negativeRegex: /path\.(?:resolve|join|normalize)\s*\(.*?\.\..*?(?:includes|startsWith)/i,
      },
      {
        regex: /path\.(?:join|resolve)\s*\(.*?(?:req\.|request\.|params|query|body)/i,
        negativeRegex: /\.replace\s*\(\s*['"]\.\.['"]/i,
      },
      {
        regex: /open\s*\(.*?(?:request|input|args).*?['"]\s*(?:r|rb|w|wb|a)/i,
      },
      {
        regex: /\.sendFile\s*\(.*?(?:req\.|request\.|params|query)/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Validate and sanitize file paths. Use path.resolve() and verify the resolved path stays within allowed directory.',
      descriptionKo: '파일 경로를 검증하고 새니타이즈하세요. path.resolve()를 사용하고 허용된 디렉토리 내에 있는지 확인하세요.',
      secureExample: `// ✅ Secure: Validate resolved path stays within base directory
const basePath = path.resolve('./uploads');
const filePath = path.resolve(basePath, userInput);
if (!filePath.startsWith(basePath)) {
  throw new Error('Invalid file path');
}`,
      references: [
        'https://cwe.mitre.org/data/definitions/22.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
      ],
    },
    tags: ['path-traversal', 'lfi', 'file-access'],
  },

  {
    id: 'SCG-INJ-SSRF-001',
    title: 'Server-Side Request Forgery (SSRF)',
    titleKo: '서버 사이드 요청 위조 (SSRF)',
    severity: 'high',
    confidence: 'medium',
    category: 'A10:2021-SSRF',
    cweId: 'CWE-918',
    owaspCategory: 'A10',
    description: 'User-controlled URL is used in server-side HTTP request without validation.',
    descriptionKo: '사용자가 제어하는 URL이 검증 없이 서버 측 HTTP 요청에 사용됩니다.',
    patterns: [
      {
        regex: /(?:fetch|axios|got|request|http\.get|https\.get|urllib)\s*\(.*?(?:req\.|request\.|params|query|body|input|url)/i,
        negativeRegex: /(?:allowlist|whitelist|isAllowedUrl|validateUrl)/i,
      },
      {
        regex: /(?:fetch|axios\.get|axios\.post)\s*\(\s*`[^`]*\$\{.*?(?:req|request|params|query|body)/i,
      },
      {
        regex: /requests\.(?:get|post|put|delete)\s*\(.*?(?:request|input|args)/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Validate and restrict URLs to allowed domains. Block internal IP ranges.',
      descriptionKo: 'URL을 허용된 도메인으로 제한하세요. 내부 IP 대역을 차단하세요.',
      secureExample: `// ✅ Secure: URL allowlist validation
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];
const url = new URL(userInput);
if (!ALLOWED_HOSTS.includes(url.hostname)) {
  throw new Error('URL not allowed');
}`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['ssrf', 'owasp-top10'],
  },

  {
    id: 'SCG-INJ-TMPL-001',
    title: 'Template Injection (SSTI)',
    titleKo: '서버 사이드 템플릿 인젝션',
    severity: 'critical',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-1336',
    owaspCategory: 'A03',
    description: 'User input is passed directly to a template engine, allowing server-side template injection.',
    descriptionKo: '사용자 입력이 템플릿 엔진에 직접 전달되어 서버 사이드 템플릿 인젝션에 노출됩니다.',
    patterns: [
      {
        regex: /(?:render_template_string|Template)\s*\(.*?(?:request|input|args)/i,
      },
      {
        regex: /(?:Handlebars|ejs|pug)\.(?:compile|render)\s*\(.*?(?:req\.|request\.|body|query)/i,
      },
      {
        regex: /nunjucks\.renderString\s*\(.*?(?:req\.|request\.|body|query)/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Never pass user input as template source. Use template data context instead.',
      descriptionKo: '사용자 입력을 템플릿 소스로 전달하지 마세요. 템플릿 데이터 컨텍스트를 사용하세요.',
      secureExample: `// ✅ Secure: Pass user data as context, not as template
res.render('template', { name: req.body.name });`,
      references: [
        'https://portswigger.net/web-security/server-side-template-injection',
      ],
    },
    tags: ['ssti', 'template-injection', 'rce'],
  },

  {
    id: 'SCG-INJ-LOG-001',
    title: 'Log Injection',
    titleKo: '로그 인젝션',
    severity: 'medium',
    confidence: 'medium',
    category: 'A09:2021-Security Logging and Monitoring Failures',
    cweId: 'CWE-117',
    owaspCategory: 'A09',
    description: 'User input is logged without sanitization, allowing log injection/forging.',
    descriptionKo: '사용자 입력이 새니타이즈 없이 로그에 기록되어 로그 인젝션/위조에 노출됩니다.',
    patterns: [
      {
        regex: /(?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug))\s*\(.*?(?:req\.|request\.)(?:body|query|params|headers)/i,
        negativeRegex: /sanitize|escape|replace.*\\n/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Sanitize user input before logging. Remove newlines and control characters.',
      descriptionKo: '로그 기록 전 사용자 입력을 새니타이즈하세요. 개행문자와 제어문자를 제거하세요.',
      secureExample: `// ✅ Secure: Sanitize before logging
const sanitized = userInput.replace(/[\\n\\r\\t]/g, '_');
logger.info(\`Login attempt for user: \${sanitized}\`);`,
      references: ['https://cwe.mitre.org/data/definitions/117.html'],
    },
    tags: ['log-injection', 'logging'],
  },

  {
    id: 'SCG-INJ-HDR-001',
    title: 'HTTP Header Injection (CRLF)',
    titleKo: 'HTTP 헤더 인젝션 (CRLF)',
    severity: 'high',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-113',
    owaspCategory: 'A03',
    description: 'User input is used in HTTP header values without CRLF sanitization.',
    descriptionKo: '사용자 입력이 CRLF 새니타이즈 없이 HTTP 헤더 값에 사용됩니다.',
    patterns: [
      {
        regex: /(?:setHeader|writeHead|res\.set|res\.header)\s*\(.*?(?:req\.|request\.|body|query|params)/i,
        negativeRegex: /\.replace\s*\(.*?\\r|\\n/i,
      },
      {
        regex: /(?:res\.redirect)\s*\(.*?(?:req\.|request\.|body|query|params)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Sanitize user input in HTTP headers. Remove CRLF characters (\\r\\n).',
      descriptionKo: 'HTTP 헤더의 사용자 입력을 새니타이즈하세요. CRLF 문자(\\r\\n)를 제거하세요.',
      secureExample: `// ✅ Secure: Strip CRLF before setting header
const safeValue = userInput.replace(/[\\r\\n]/g, '');
res.setHeader('X-Custom', safeValue);`,
      references: ['https://cwe.mitre.org/data/definitions/113.html'],
    },
    tags: ['crlf', 'header-injection', 'http-splitting'],
  },

  {
    id: 'SCG-INJ-DESER-001',
    title: 'Insecure Deserialization',
    titleKo: '안전하지 않은 역직렬화',
    severity: 'critical',
    confidence: 'medium',
    category: 'A08:2021-Software and Data Integrity Failures',
    cweId: 'CWE-502',
    owaspCategory: 'A08',
    description: 'Untrusted data is deserialized without validation, allowing remote code execution.',
    descriptionKo: '신뢰할 수 없는 데이터가 검증 없이 역직렬화되어 원격 코드 실행에 노출됩니다.',
    patterns: [
      {
        regex: /(?:pickle\.loads|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)|unserialize|ObjectInputStream)/i,
        negativeRegex: /SafeLoader|safe_load/i,
      },
      {
        regex: /node-serialize|serialize-javascript.*?\bunserialize\b/i,
      },
      {
        regex: /yaml\.load\s*\([^)]*\)\s*(?!.*SafeLoader)/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Use safe deserialization methods. Validate data integrity before deserializing.',
      descriptionKo: '안전한 역직렬화 메서드를 사용하세요. 역직렬화 전 데이터 무결성을 검증하세요.',
      secureExample: `# ✅ Python: Use safe YAML loader
import yaml
data = yaml.safe_load(user_input)

# ✅ Python: Use JSON instead of pickle for untrusted data
import json
data = json.loads(user_input)`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
      ],
    },
    tags: ['deserialization', 'rce'],
  },
];
