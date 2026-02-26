import type { SecurityRule } from '../types/index.js';

export const serverRules: SecurityRule[] = [
  // ── Prototype Pollution ──
  {
    id: 'SCG-SRV-PROTO-001',
    title: 'Prototype Pollution via Object Merge',
    titleKo: '객체 병합을 통한 프로토타입 오염',
    severity: 'critical',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-1321',
    owaspCategory: 'A03',
    description: 'Merging user input into objects without sanitization can lead to prototype pollution, enabling property injection or RCE.',
    descriptionKo: '사용자 입력을 검증 없이 객체에 병합하면 프로토타입 오염이 발생하여 속성 주입 또는 원격 코드 실행이 가능합니다.',
    patterns: [
      {
        regex: /Object\.assign\s*\(\s*\{\}\s*,\s*(?:req\.body|req\.query|req\.params|request\.body|input|payload|data|params|args)/i,
        negativeRegex: /safeMerge|sanitize|validate|schema\.parse|zod|joi/i,
      },
      {
        regex: /(?:_\.merge|_\.defaultsDeep|_\.set|merge|deepMerge|extend)\s*\([^,]*,\s*(?:req\.body|req\.query|req\.params|request\.body|input|payload|data|args)/i,
        negativeRegex: /safeMerge|sanitize|validate/i,
      },
      {
        regex: /\bJSON\.parse\s*\(.*?(?:req\.body|req\.query|request\.body|input)\b/i,
        negativeRegex: /try\s*\{|catch|schema|validate|zod|joi/i,
      },
      {
        regex: /\[(?:req\.body|req\.query|input|key|prop|name)\[/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Validate and sanitize user input before merging. Use schema validation (zod/joi). Freeze prototypes or use Object.create(null).',
      descriptionKo: '병합 전 사용자 입력을 검증/새니타이즈하세요. zod/joi 스키마 검증을 사용하세요. Object.create(null) 또는 Object.freeze(Object.prototype)을 활용하세요.',
      secureExample: `// ✅ Secure: Schema validation before merge
import { z } from 'zod';
const schema = z.object({ name: z.string(), age: z.number() });
const validated = schema.parse(req.body);

// ✅ Secure: Use Object.create(null) as target
const safeObj = Object.assign(Object.create(null), validated);

// ✅ Secure: Block __proto__ and constructor keys
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    target[key] = source[key];
  }
  return target;
}`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/1321.html',
      ],
    },
    tags: ['prototype-pollution', 'rce', 'server', 'nodejs'],
  },

  // ── XXE (XML External Entity) ──
  {
    id: 'SCG-SRV-XXE-001',
    title: 'XML External Entity (XXE) Injection',
    titleKo: 'XML 외부 엔티티(XXE) 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-611',
    owaspCategory: 'A05',
    description: 'Parsing XML input without disabling external entities can lead to file disclosure, SSRF, or denial of service.',
    descriptionKo: '외부 엔티티를 비활성화하지 않고 XML을 파싱하면 파일 노출, SSRF, DoS 공격에 노출됩니다.',
    patterns: [
      {
        regex: /(?:DOMParser|xml2js|libxmljs|fast-xml-parser|sax|xmldom|parseString|parseXml)\s*[\.(]/i,
        negativeRegex: /noent:\s*false|resolve_entities.*false|disallow.*doctype|FORBID_DTD/i,
      },
      {
        regex: /DocumentBuilderFactory|SAXParserFactory|XMLInputFactory/i,
        negativeRegex: /setFeature.*disallow-doctype-decl|SUPPORT_DTD.*false/i,
      },
      {
        regex: /etree\.parse|etree\.fromstring|minidom\.parse|pulldom\.parse|sax\.parse/i,
        negativeRegex: /defusedxml|resolve_entities.*False/i,
      },
      {
        regex: /lxml\.etree/i,
        negativeRegex: /resolve_entities.*False|no_network.*True/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java'],
    remediation: {
      description: 'Disable external entities and DTD processing in XML parsers. Use defusedxml in Python.',
      descriptionKo: 'XML 파서에서 외부 엔티티와 DTD 처리를 비활성화하세요. Python은 defusedxml을 사용하세요.',
      secureExample: `// ✅ Node.js: Disable entities in xml2js
const xml2js = require('xml2js');
const parser = new xml2js.Parser({ explicitCharkey: true });

// ✅ Java: Disable DTD in DocumentBuilderFactory
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

# ✅ Python: Use defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(xml_input)`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/611.html',
      ],
    },
    tags: ['xxe', 'xml', 'server', 'ssrf', 'file-disclosure'],
  },

  // ── File Upload Security ──
  {
    id: 'SCG-SRV-UPLOAD-001',
    title: 'Insecure File Upload',
    titleKo: '안전하지 않은 파일 업로드',
    severity: 'high',
    confidence: 'medium',
    category: 'A04:2021-Insecure Design',
    cweId: 'CWE-434',
    owaspCategory: 'A04',
    description: 'File upload without proper type/size validation can lead to arbitrary file upload, path traversal, or RCE.',
    descriptionKo: '파일 타입/크기 검증 없는 업로드는 임의 파일 업로드, 경로 탐색, 원격 코드 실행으로 이어질 수 있습니다.',
    patterns: [
      {
        regex: /multer\s*\(\s*\{[^}]*dest\s*:/i,
        negativeRegex: /fileFilter|limits|mimetype|allowedTypes/i,
      },
      {
        regex: /multer\s*\(\s*\{\s*\}\s*\)/i,
      },
      {
        regex: /\.upload\s*\.\s*(?:single|array|fields)\s*\(/i,
        negativeRegex: /fileFilter|limits|validator|validate/i,
      },
      {
        regex: /(?:req\.file|req\.files)(?:\.(?:originalname|path|buffer))/i,
        negativeRegex: /mimetype|fileType|allowedExt|validate|sanitize/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Validate file type (MIME type + magic bytes), size, and filename. Store outside webroot. Generate random filenames.',
      descriptionKo: '파일 타입(MIME + 매직바이트), 크기, 파일명을 검증하세요. 웹루트 밖에 저장하세요. 랜덤 파일명을 사용하세요.',
      secureExample: `// ✅ Secure: multer with validation
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'), false);
    }
    cb(null, true);
  },
  storage: multer.diskStorage({
    destination: '/secure/uploads/',
    filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname)),
  }),
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/434.html',
      ],
    },
    tags: ['file-upload', 'rce', 'server', 'express'],
  },

  // ── child_process with shell: true ──
  {
    id: 'SCG-SRV-CMD-001',
    title: 'Command Injection via shell option',
    titleKo: 'shell 옵션을 통한 명령어 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-78',
    owaspCategory: 'A03',
    description: 'Using child_process.spawn/exec with shell:true and user input enables command injection.',
    descriptionKo: 'child_process.spawn/exec에 shell:true와 사용자 입력을 함께 사용하면 명령어 인젝션이 가능합니다.',
    patterns: [
      {
        regex: /(?:spawn|execFile)\s*\([^)]*\{[^}]*shell\s*:\s*true/i,
        negativeRegex: /sanitize|escape|whitelist|allowedCmd/i,
      },
      {
        regex: /subprocess\.(?:Popen|call|run)\s*\([^)]*shell\s*=\s*True/i,
        negativeRegex: /shlex\.quote|sanitize/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Avoid shell:true. Use spawn with arguments array. In Python, avoid shell=True and use shlex.quote().',
      descriptionKo: 'shell:true를 피하세요. spawn에 인수 배열을 사용하세요. Python은 shell=True를 피하고 shlex.quote()를 사용하세요.',
      secureExample: `// ✅ Secure: spawn without shell
const { spawn } = require('child_process');
const proc = spawn('ls', ['-la', sanitizedPath]);

# ✅ Python: Avoid shell=True
import subprocess, shlex
subprocess.run(['ls', '-la', shlex.quote(user_input)])`,
      references: [
        'https://cwe.mitre.org/data/definitions/78.html',
      ],
    },
    tags: ['command-injection', 'rce', 'server', 'child-process'],
  },

  // ── Missing Express Security Middleware ──
  {
    id: 'SCG-SRV-EXPRESS-001',
    title: 'Express app without trust proxy',
    titleKo: 'Express trust proxy 미설정',
    severity: 'medium',
    confidence: 'medium',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-346',
    owaspCategory: 'A05',
    description: 'Express app behind a reverse proxy without trust proxy setting may incorrectly identify client IPs, breaking rate limiting and logging.',
    descriptionKo: '리버스 프록시 뒤에서 trust proxy 없이 운영하면 클라이언트 IP 식별이 잘못되어 rate limiting과 로깅이 제대로 동작하지 않습니다.',
    patterns: [
      {
        regex: /app\.listen\s*\(/i,
        negativeRegex: /trust\s*proxy|app\.set\s*\(\s*['"]trust proxy['"]/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Set trust proxy when behind a reverse proxy (nginx, load balancer).',
      descriptionKo: '리버스 프록시(nginx, 로드밸런서) 뒤에서 운영 시 trust proxy를 설정하세요.',
      secureExample: `// ✅ Secure: Set trust proxy
app.set('trust proxy', 1); // trust first proxy`,
      references: [
        'https://expressjs.com/en/guide/behind-proxies.html',
      ],
    },
    tags: ['express', 'proxy', 'server', 'configuration'],
  },

  // ── Missing Request Body Size Limit ──
  {
    id: 'SCG-SRV-DOS-001',
    title: 'Missing Request Body Size Limit',
    titleKo: '요청 본문 크기 제한 미설정',
    severity: 'medium',
    confidence: 'medium',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-770',
    owaspCategory: 'A05',
    description: 'Express JSON/URL-encoded parser without size limit can be exploited for denial of service via large payloads.',
    descriptionKo: '크기 제한 없는 JSON/URL-encoded 파서는 대용량 페이로드를 통한 서비스 거부 공격에 취약합니다.',
    patterns: [
      {
        regex: /express\.json\s*\(\s*\)/i,
      },
      {
        regex: /express\.urlencoded\s*\(\s*\{[^}]*extended/i,
        negativeRegex: /limit\s*:/i,
      },
      {
        regex: /bodyParser\.json\s*\(\s*\)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Set explicit body size limits on all body parsers.',
      descriptionKo: '모든 바디 파서에 명시적 크기 제한을 설정하세요.',
      secureExample: `// ✅ Secure: Limit body size
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));`,
      references: [
        'https://cwe.mitre.org/data/definitions/770.html',
      ],
    },
    tags: ['dos', 'express', 'server', 'body-parser'],
  },

  // ── JWT Algorithm Confusion ──
  {
    id: 'SCG-SRV-JWT-001',
    title: 'JWT Algorithm Confusion / None Algorithm',
    titleKo: 'JWT 알고리즘 혼동 / none 알고리즘',
    severity: 'critical',
    confidence: 'high',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-345',
    owaspCategory: 'A02',
    description: 'JWT verified without specifying algorithms allows algorithm confusion attacks (e.g., switching RS256 to HS256 or "none").',
    descriptionKo: 'JWT 검증 시 알고리즘을 명시하지 않으면 알고리즘 혼동 공격(RS256→HS256 전환 또는 "none")이 가능합니다.',
    patterns: [
      {
        regex: /jwt\.verify\s*\([^)]*\)\s*(?!.*algorithms)/i,
        negativeRegex: /algorithms\s*:\s*\[/i,
      },
      {
        regex: /algorithm\s*:\s*['"]none['"]/i,
      },
      {
        regex: /jwt\.decode\s*\(/i,
        negativeRegex: /\/\/.*jwt\.decode|verify/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Always specify allowed algorithms in jwt.verify(). Never use jwt.decode() for authentication.',
      descriptionKo: 'jwt.verify()에 반드시 허용 알고리즘을 명시하세요. 인증에 jwt.decode()를 절대 사용하지 마세요.',
      secureExample: `// ✅ Secure: Specify algorithms
const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });

// ✅ Secure: RS256 with public key
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/345.html',
      ],
    },
    tags: ['jwt', 'authentication', 'server', 'algorithm-confusion'],
  },

  // ── SSRF via Cloud Metadata ──
  {
    id: 'SCG-SRV-SSRF-001',
    title: 'SSRF via Cloud Metadata Endpoint',
    titleKo: '클라우드 메타데이터 엔드포인트를 통한 SSRF',
    severity: 'critical',
    confidence: 'high',
    category: 'A10:2021-Server-Side Request Forgery',
    cweId: 'CWE-918',
    owaspCategory: 'A10',
    description: 'Server-side HTTP requests with user-controlled URLs without blocking internal/metadata IPs enable SSRF attacks.',
    descriptionKo: '사용자가 제어하는 URL로 서버 사이드 HTTP 요청 시 내부/메타데이터 IP를 차단하지 않으면 SSRF 공격에 노출됩니다.',
    patterns: [
      {
        regex: /(?:fetch|axios|got|request|http\.get|urllib|requests\.get)\s*\(\s*(?:req\.body|req\.query|req\.params|input|url|user|data)\b/i,
        negativeRegex: /allowlist|whitelist|validateUrl|isAllowedUrl|blockPrivate/i,
      },
      {
        regex: /(?:fetch|axios|got|request)\s*\(\s*`\$\{/i,
        negativeRegex: /allowlist|whitelist|validateUrl/i,
      },
      {
        regex: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Validate and whitelist URLs. Block internal IPs (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use URL parsing to prevent bypass.',
      descriptionKo: 'URL을 검증하고 화이트리스트를 사용하세요. 내부 IP(10.x, 172.16-31.x, 192.168.x, 169.254.x)를 차단하세요.',
      secureExample: `// ✅ Secure: URL validation with blocklist
function isAllowedUrl(input) {
  const url = new URL(input);
  const blocked = ['127.0.0.1', 'localhost', '169.254.169.254', '0.0.0.0'];
  if (blocked.includes(url.hostname)) throw new Error('Blocked');
  if (/^(10\.|172\.(1[6-9]|2\\d|3[01])\.|192\\.168\\.)/.test(url.hostname)) throw new Error('Blocked');
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Invalid protocol');
  return url.toString();
}`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['ssrf', 'server', 'cloud', 'metadata'],
  },

  // ── NoSQL Injection Enhanced ──
  {
    id: 'SCG-SRV-NOSQL-001',
    title: 'NoSQL Operator Injection',
    titleKo: 'NoSQL 연산자 인젝션',
    severity: 'critical',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-943',
    owaspCategory: 'A03',
    description: 'Passing user input directly to MongoDB query operators ($where, $gt, $regex) enables NoSQL injection.',
    descriptionKo: '사용자 입력을 MongoDB 쿼리 연산자($where, $gt, $regex)에 직접 전달하면 NoSQL 인젝션이 가능합니다.',
    patterns: [
      {
        regex: /\$where\s*:\s*(?:req\.|input|data|user|params|args)/i,
      },
      {
        regex: /\.find\s*\(\s*(?:req\.body|req\.query|req\.params|input|data|payload)\s*\)/i,
        negativeRegex: /sanitize|validate|schema|mongoose\.Types\.ObjectId/i,
      },
      {
        regex: /\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists)\s*:\s*(?:req\.|input|body|query|params)/i,
        negativeRegex: /sanitize|validate|parseInt|Number\(/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Validate input types strictly. Never pass raw user input to MongoDB queries. Use mongo-sanitize or explicit type casting.',
      descriptionKo: '입력 타입을 엄격히 검증하세요. MongoDB 쿼리에 사용자 입력을 직접 전달하지 마세요. mongo-sanitize 또는 명시적 타입 캐스팅을 사용하세요.',
      secureExample: `// ✅ Secure: Validate and sanitize
import mongoSanitize from 'express-mongo-sanitize';
app.use(mongoSanitize());

// ✅ Secure: Explicit type casting
const userId = new mongoose.Types.ObjectId(req.params.id);
const user = await User.findById(userId);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/943.html',
      ],
    },
    tags: ['nosql', 'mongodb', 'injection', 'server'],
  },

  // ── Missing Input Validation Middleware ──
  {
    id: 'SCG-SRV-VALID-001',
    title: 'Express Route Without Input Validation',
    titleKo: '입력 검증 없는 Express 라우트',
    severity: 'high',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-20',
    owaspCategory: 'A03',
    description: 'Express route handler directly accesses req.body/query/params without schema validation.',
    descriptionKo: 'Express 라우트 핸들러가 스키마 검증 없이 req.body/query/params에 직접 접근합니다.',
    patterns: [
      {
        regex: /(?:app|router)\.\s*(?:post|put|patch)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s*)?\(?(?:req|request)/i,
        negativeRegex: /validate|validator|schema|zod|joi|celebrate|checkSchema|body\(|param\(|query\(/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Use validation middleware (zod, joi, express-validator) before route handlers.',
      descriptionKo: '라우트 핸들러 앞에 검증 미들웨어(zod, joi, express-validator)를 사용하세요.',
      secureExample: `// ✅ Secure: Zod validation middleware
import { z } from 'zod';
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(8) });

app.post('/login', (req, res) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ errors: result.error.issues });
  // proceed with validated data
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
      ],
    },
    tags: ['validation', 'express', 'server', 'input'],
  },

  // ── Sensitive Data in Error Response ──
  {
    id: 'SCG-SRV-ERR-001',
    title: 'Stack Trace / Internal Error Exposed to Client',
    titleKo: '스택 트레이스/내부 에러가 클라이언트에 노출',
    severity: 'medium',
    confidence: 'medium',
    category: 'A04:2021-Insecure Design',
    cweId: 'CWE-209',
    owaspCategory: 'A04',
    description: 'Sending error stack traces or internal error details to clients leaks server internals.',
    descriptionKo: '에러 스택 트레이스나 내부 에러 상세를 클라이언트에 전송하면 서버 내부 정보가 노출됩니다.',
    patterns: [
      {
        regex: /res\.(?:json|send)\s*\(\s*(?:err|error|e)\s*\)/i,
        negativeRegex: /message|\.message|statusCode|production/i,
      },
      {
        regex: /res\.(?:json|send)\s*\(\s*\{[^}]*stack\s*:/i,
      },
      {
        regex: /res\.status\s*\(\s*500\s*\)\.(?:json|send)\s*\(\s*(?:err|error)\s*\)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Return generic error messages to clients. Log full errors server-side only.',
      descriptionKo: '클라이언트에는 일반적인 에러 메시지를 반환하세요. 전체 에러는 서버 측에서만 로깅하세요.',
      secureExample: `// ✅ Secure: Generic error response
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: '서버 오류가 발생했습니다.' });
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
      ],
    },
    tags: ['error-handling', 'information-disclosure', 'server', 'express'],
  },

  // ── Missing HSTS ──
  {
    id: 'SCG-SRV-HSTS-001',
    title: 'Missing HTTP Strict Transport Security (HSTS)',
    titleKo: 'HSTS(HTTP 엄격 전송 보안) 미설정',
    severity: 'medium',
    confidence: 'medium',
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-319',
    owaspCategory: 'A05',
    description: 'Missing HSTS header allows downgrade attacks from HTTPS to HTTP.',
    descriptionKo: 'HSTS 헤더가 없으면 HTTPS에서 HTTP로의 다운그레이드 공격이 가능합니다.',
    patterns: [
      {
        regex: /app\.listen\s*\(\s*(?:443|process\.env\.PORT)/i,
        negativeRegex: /Strict-Transport-Security|hsts|helmet/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['express'],
    remediation: {
      description: 'Add HSTS header via helmet or manually. Set max-age to at least 1 year.',
      descriptionKo: 'helmet 또는 수동으로 HSTS 헤더를 추가하세요. max-age를 최소 1년으로 설정하세요.',
      secureExample: `// ✅ Secure: HSTS via helmet
const helmet = require('helmet');
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));

// ✅ Secure: Manual HSTS header
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
      ],
    },
    tags: ['hsts', 'tls', 'server', 'headers'],
  },

  // ── Unvalidated Redirect ──
  {
    id: 'SCG-SRV-REDIR-001',
    title: 'Open Redirect via User Input',
    titleKo: '사용자 입력을 통한 오픈 리다이렉트',
    severity: 'medium',
    confidence: 'high',
    category: 'A01:2021-Broken Access Control',
    cweId: 'CWE-601',
    owaspCategory: 'A01',
    description: 'Using user-controlled input in redirect URLs enables phishing via open redirect.',
    descriptionKo: '사용자가 제어하는 입력을 리다이렉트 URL에 사용하면 오픈 리다이렉트를 통한 피싱이 가능합니다.',
    patterns: [
      {
        regex: /res\.redirect\s*\(\s*(?:req\.query|req\.body|req\.params)\./i,
        negativeRegex: /whitelist|allowedUrl|isRelative|startsWith\s*\(\s*['"]\//i,
      },
      {
        regex: /redirect\s*\(\s*(?:url|next|returnUrl|callback|redirect_uri)\s*\)/i,
        negativeRegex: /whitelist|allowedUrl|validate/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Validate redirect URLs against a whitelist. Only allow relative paths or known domains.',
      descriptionKo: '리다이렉트 URL을 화이트리스트로 검증하세요. 상대 경로 또는 알려진 도메인만 허용하세요.',
      secureExample: `// ✅ Secure: Validate redirect URL
function safeRedirect(req, res, fallback = '/') {
  const url = req.query.next;
  if (!url || !url.startsWith('/') || url.startsWith('//')) {
    return res.redirect(fallback);
  }
  res.redirect(url);
}`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
      ],
    },
    tags: ['open-redirect', 'phishing', 'server'],
  },

  // ── IDOR (Insecure Direct Object Reference) ──
  {
    id: 'SCG-SRV-IDOR-001',
    title: 'Insecure Direct Object Reference (IDOR)',
    titleKo: '안전하지 않은 직접 객체 참조(IDOR)',
    severity: 'high',
    confidence: 'medium',
    category: 'A01:2021-Broken Access Control',
    cweId: 'CWE-639',
    owaspCategory: 'A01',
    description: 'Accessing resources by user-supplied ID without ownership verification enables unauthorized access.',
    descriptionKo: '소유자 확인 없이 사용자가 제공한 ID로 리소스에 접근하면 무단 접근이 가능합니다.',
    patterns: [
      {
        regex: /(?:findById|findByPk|findOne|get)\s*\(\s*req\.params\.id\s*\)/i,
        negativeRegex: /userId|user_id|owner|author|createdBy|req\.user/i,
      },
      {
        regex: /(?:UPDATE|DELETE)\s.*?WHERE\s+id\s*=\s*(?:\$\d|\?)/i,
        negativeRegex: /AND\s+(?:user_id|owner_id|author_id|created_by)\s*=/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Always verify resource ownership. Include user ID in all queries that access user-specific resources.',
      descriptionKo: '항상 리소스 소유권을 확인하세요. 사용자별 리소스에 접근하는 모든 쿼리에 사용자 ID를 포함하세요.',
      secureExample: `// ✅ Secure: Verify ownership
const post = await Post.findOne({
  where: { id: req.params.id, authorId: req.user.id }
});
if (!post) return res.status(404).json({ error: 'Not found' });`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['idor', 'authorization', 'server', 'access-control'],
  },
];
