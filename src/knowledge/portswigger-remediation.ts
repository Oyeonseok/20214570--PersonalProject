export interface PortSwiggerKnowledge {
  category: string;
  cweIds: string[];
  title: string;
  titleKo: string;
  attackMechanism: string;
  attackMechanismKo: string;
  attackTypes: string[];
  impactDescription: string;
  preventionTechniques: string[];
  preventionTechniquesKo: string[];
  secureCodeExample: string;
  commonMistakes: string[];
  commonMistakesKo: string[];
  portswiggerUrl: string;
}

const PORTSWIGGER_KB: PortSwiggerKnowledge[] = [
  {
    category: 'sql-injection',
    cweIds: ['CWE-89', 'CWE-564'],
    title: 'SQL Injection',
    titleKo: 'SQL 인젝션',
    attackMechanism: 'Attacker injects malicious SQL fragments into application queries via user input, altering query logic to access/modify unauthorized data.',
    attackMechanismKo: '공격자가 사용자 입력을 통해 악의적인 SQL 구문을 애플리케이션 쿼리에 주입하여 무단으로 데이터를 접근/수정합니다.',
    attackTypes: ['Union-based', 'Boolean-based blind', 'Time-based blind', 'Error-based', 'Out-of-band (OOB)', 'Second-order'],
    impactDescription: 'Full database access, data exfiltration, data modification/deletion, authentication bypass, potential RCE via xp_cmdshell or file operations.',
    preventionTechniques: [
      'Use parameterized queries (prepared statements) for ALL database interactions',
      'Use ORM with parameterized methods (never raw SQL with string concatenation)',
      'Apply whitelist input validation for table/column names in ORDER BY',
      'Apply least-privilege database accounts',
      'Deploy WAF rules as defense-in-depth',
    ],
    preventionTechniquesKo: [
      '모든 DB 상호작용에 파라미터화 쿼리(prepared statement) 사용',
      'ORM의 파라미터화 메서드 사용 (문자열 연결 raw SQL 금지)',
      'ORDER BY 등의 테이블/컬럼명에 화이트리스트 입력 검증 적용',
      '최소 권한 DB 계정 적용',
      'WAF 규칙을 심층 방어로 배포',
    ],
    secureCodeExample: `// Parameterized query (Node.js + pg)
const { rows } = await pool.query(
  'SELECT * FROM users WHERE email = $1 AND status = $2',
  [email, 'active']
);`,
    commonMistakes: [
      'Using template literals for SQL queries',
      'Trusting ORM .raw() methods with user input',
      'Only filtering SELECT but missing INSERT/UPDATE',
      'Blacklist-based filtering instead of parameterization',
    ],
    commonMistakesKo: [
      '템플릿 리터럴로 SQL 쿼리 작성',
      'ORM .raw() 메서드에 사용자 입력 신뢰',
      'SELECT만 필터링하고 INSERT/UPDATE 누락',
      '파라미터화 대신 블랙리스트 필터링 사용',
    ],
    portswiggerUrl: 'https://portswigger.net/web-security/sql-injection',
  },
  {
    category: 'xss',
    cweIds: ['CWE-79', 'CWE-80'],
    title: 'Cross-Site Scripting (XSS)',
    titleKo: '크로스 사이트 스크립팅 (XSS)',
    attackMechanism: 'Attacker injects malicious scripts into web pages viewed by other users by exploiting insufficient output encoding.',
    attackMechanismKo: '불충분한 출력 인코딩을 악용하여 다른 사용자가 보는 웹 페이지에 악성 스크립트를 주입합니다.',
    attackTypes: ['Reflected XSS', 'Stored XSS', 'DOM-based XSS', 'Mutation XSS (mXSS)', 'Dangling markup injection'],
    impactDescription: 'Session hijacking, credential theft, keylogging, phishing, worm propagation, virtual defacement.',
    preventionTechniques: [
      'Encode output based on context (HTML body, attribute, JavaScript, URL, CSS)',
      'Use Content-Security-Policy (CSP) with nonce or hash',
      'Use textContent/innerText instead of innerHTML',
      'Use DOMPurify for HTML sanitization',
      'Set HttpOnly and SameSite flags on cookies',
      'Use Trusted Types API for DOM XSS prevention',
    ],
    preventionTechniquesKo: [
      '컨텍스트별 출력 인코딩 (HTML body, attribute, JS, URL, CSS)',
      'nonce/hash 기반 CSP (Content-Security-Policy) 적용',
      'innerHTML 대신 textContent/innerText 사용',
      'HTML 새니타이즈에 DOMPurify 사용',
      '쿠키에 HttpOnly, SameSite 플래그 설정',
      'DOM XSS 방지를 위한 Trusted Types API 사용',
    ],
    secureCodeExample: `// Context-aware output encoding
// HTML context: use textContent
element.textContent = userInput;
// Attribute context: use setAttribute
element.setAttribute('data-value', userInput);
// CSP header
Content-Security-Policy: default-src 'self'; script-src 'nonce-abc123'`,
    commonMistakes: [
      'Using innerHTML with user input',
      'Encoding in wrong context (HTML encode in JavaScript block)',
      'Missing CSP or using unsafe-inline',
      'Client-side sanitization only (no server-side)',
    ],
    commonMistakesKo: [
      '사용자 입력으로 innerHTML 사용',
      '잘못된 컨텍스트 인코딩 (JS 블록에서 HTML 인코딩)',
      'CSP 누락 또는 unsafe-inline 사용',
      '클라이언트 측 새니타이즈만 적용 (서버 측 없음)',
    ],
    portswiggerUrl: 'https://portswigger.net/web-security/cross-site-scripting',
  },
  {
    category: 'csrf',
    cweIds: ['CWE-352'],
    title: 'Cross-Site Request Forgery (CSRF)',
    titleKo: '크로스 사이트 요청 위조 (CSRF)',
    attackMechanism: 'Attacker tricks authenticated user into submitting unintended requests by exploiting browser auto-attach of cookies.',
    attackMechanismKo: '브라우저의 쿠키 자동 첨부를 악용하여 인증된 사용자가 의도하지 않은 요청을 보내도록 속입니다.',
    attackTypes: ['Form-based CSRF', 'Image/GET-based CSRF', 'XHR-based CSRF', 'Login CSRF'],
    impactDescription: 'Unauthorized state changes: password change, email change, fund transfer, account deletion.',
    preventionTechniques: [
      'Use SameSite=Strict or SameSite=Lax cookie attribute',
      'Implement synchronizer token pattern (CSRF tokens)',
      'Use custom request headers (X-Requested-With)',
      'Verify Origin/Referer headers',
      'Require re-authentication for sensitive actions',
    ],
    preventionTechniquesKo: [
      'SameSite=Strict 또는 SameSite=Lax 쿠키 속성 사용',
      '동기화 토큰 패턴 (CSRF 토큰) 구현',
      '커스텀 요청 헤더 (X-Requested-With) 사용',
      'Origin/Referer 헤더 검증',
      '민감한 작업에 재인증 요구',
    ],
    secureCodeExample: `// Express CSRF protection
import csrf from 'csurf';
app.use(csrf({ cookie: { sameSite: 'strict', httpOnly: true } }));
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});`,
    commonMistakes: [
      'State-changing operations via GET requests',
      'CSRF token in query string (leaked via Referer)',
      'Token not bound to user session',
      'Missing SameSite cookie attribute',
    ],
    commonMistakesKo: [
      'GET 요청으로 상태 변경 작업 수행',
      'CSRF 토큰을 쿼리 스트링에 포함 (Referer로 유출)',
      '토큰이 사용자 세션에 바인딩되지 않음',
      'SameSite 쿠키 속성 누락',
    ],
    portswiggerUrl: 'https://portswigger.net/web-security/csrf',
  },
  {
    category: 'ssrf',
    cweIds: ['CWE-918'],
    title: 'Server-Side Request Forgery (SSRF)',
    titleKo: '서버 측 요청 위조 (SSRF)',
    attackMechanism: 'Attacker makes the server send requests to unintended locations, accessing internal services or cloud metadata.',
    attackMechanismKo: '서버가 의도하지 않은 위치로 요청을 보내도록 하여 내부 서비스나 클라우드 메타데이터에 접근합니다.',
    attackTypes: ['Basic SSRF', 'Blind SSRF', 'DNS rebinding', 'SSRF via URL parsers', 'SSRF via redirects'],
    impactDescription: 'Access to internal services, cloud metadata (AWS IAM credentials), port scanning, RCE via internal APIs.',
    preventionTechniques: [
      'Whitelist allowed domains/IPs for outgoing requests',
      'Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.169.254)',
      'Disable HTTP redirects or validate redirect targets',
      'Use DNS resolution validation to prevent DNS rebinding',
      'Apply network segmentation for internal services',
    ],
    preventionTechniquesKo: [
      '외부 요청에 허용 도메인/IP 화이트리스트 적용',
      '사설 IP 대역 차단 (10.x, 172.16-31.x, 192.168.x, 169.254.169.254)',
      'HTTP 리다이렉트 비활성화 또는 리다이렉트 대상 검증',
      'DNS rebinding 방지를 위한 DNS 확인 검증',
      '내부 서비스에 네트워크 세그먼테이션 적용',
    ],
    secureCodeExample: `// URL validation for SSRF prevention
function validateUrl(url: string): boolean {
  const parsed = new URL(url);
  const blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '169.254.169.254'];
  if (blocked.includes(parsed.hostname)) return false;
  if (/^(10\\.|172\\.(1[6-9]|2|3[01])\\.|192\\.168\\.)/.test(parsed.hostname)) return false;
  if (parsed.protocol !== 'https:') return false;
  return allowedHosts.includes(parsed.hostname);
}`,
    commonMistakes: [
      'Only checking URL string without DNS resolution',
      'Allowing HTTP redirects to bypass URL validation',
      'Not blocking IPv6 loopback (::1)',
      'Trusting user-provided URLs for webhooks/callbacks',
    ],
    commonMistakesKo: [
      'DNS 확인 없이 URL 문자열만 검사',
      'URL 검증 우회를 위한 HTTP 리다이렉트 허용',
      'IPv6 루프백(::1) 미차단',
      '웹훅/콜백에 사용자 제공 URL 신뢰',
    ],
    portswiggerUrl: 'https://portswigger.net/web-security/ssrf',
  },
  {
    category: 'xxe',
    cweIds: ['CWE-611'],
    title: 'XML External Entity (XXE) Injection',
    titleKo: 'XML 외부 엔터티 (XXE) 인젝션',
    attackMechanism: 'Attacker exploits XML parsers that process external entity declarations to read files, perform SSRF, or cause DoS.',
    attackMechanismKo: '외부 엔터티 선언을 처리하는 XML 파서를 악용하여 파일 읽기, SSRF, DoS를 수행합니다.',
    attackTypes: ['File retrieval XXE', 'Blind XXE via out-of-band', 'XXE via file upload (SVG, DOCX)', 'Billion laughs DoS'],
    impactDescription: 'Local file disclosure, SSRF, denial of service, potential RCE.',
    preventionTechniques: [
      'Disable external entities and DTDs in XML parser configuration',
      'Use JSON instead of XML where possible',
      'Validate and sanitize XML input',
      'Use less complex data formats (JSON, YAML)',
    ],
    preventionTechniquesKo: [
      'XML 파서에서 외부 엔터티와 DTD 비활성화',
      '가능한 경우 XML 대신 JSON 사용',
      'XML 입력 검증 및 새니타이즈',
      '덜 복잡한 데이터 형식 (JSON, YAML) 사용',
    ],
    secureCodeExample: `// Disable external entities (Node.js libxmljs)
const doc = libxmljs.parseXml(xml, {
  noent: false, dtdload: false, dtdvalid: false, nonet: true
});`,
    commonMistakes: ['Using default XML parser settings', 'Processing XML from untrusted sources without validation', 'Allowing SVG/DOCX uploads without XML sanitization'],
    commonMistakesKo: ['기본 XML 파서 설정 사용', '검증 없이 신뢰할 수 없는 소스의 XML 처리', 'XML 새니타이즈 없이 SVG/DOCX 업로드 허용'],
    portswiggerUrl: 'https://portswigger.net/web-security/xxe',
  },
  {
    category: 'command-injection',
    cweIds: ['CWE-78', 'CWE-77'],
    title: 'OS Command Injection',
    titleKo: 'OS 명령어 인젝션',
    attackMechanism: 'Attacker injects OS commands via user input that is passed to shell execution functions (exec, system, etc.).',
    attackMechanismKo: '쉘 실행 함수(exec, system 등)에 전달되는 사용자 입력을 통해 OS 명령어를 주입합니다.',
    attackTypes: ['Direct injection (;, |, &&)', 'Blind injection via time delays', 'Out-of-band injection via DNS/HTTP'],
    impactDescription: 'Full server compromise, arbitrary command execution, data exfiltration, backdoor installation.',
    preventionTechniques: [
      'Never pass user input to shell commands',
      'Use execFile() with argument arrays (no shell interpolation)',
      'Apply strict whitelist input validation',
      'Use language-native APIs instead of shell commands',
      'Run application with minimal OS privileges',
    ],
    preventionTechniquesKo: [
      '사용자 입력을 쉘 명령에 절대 전달하지 않기',
      'execFile()과 인자 배열 사용 (쉘 인터폴레이션 없음)',
      '엄격한 화이트리스트 입력 검증 적용',
      '쉘 명령 대신 언어 네이티브 API 사용',
      '최소 OS 권한으로 애플리케이션 실행',
    ],
    secureCodeExample: `// Safe: execFile with argument array
import { execFile } from 'child_process';
execFile('convert', [inputPath, '-resize', '200x200', outputPath], (err) => { ... });`,
    commonMistakes: ['Using exec() instead of execFile()', 'Using shell: true in spawn/execFile', 'Blacklist filtering of shell metacharacters'],
    commonMistakesKo: ['execFile() 대신 exec() 사용', 'spawn/execFile에서 shell: true 사용', '쉘 메타문자 블랙리스트 필터링'],
    portswiggerUrl: 'https://portswigger.net/web-security/os-command-injection',
  },
  {
    category: 'directory-traversal',
    cweIds: ['CWE-22'],
    title: 'Directory Traversal (Path Traversal)',
    titleKo: '디렉터리 탐색 (경로 탐색)',
    attackMechanism: 'Attacker manipulates file paths to access files outside the intended directory using ../ sequences.',
    attackMechanismKo: '../ 시퀀스를 사용하여 의도된 디렉터리 외부의 파일에 접근하도록 파일 경로를 조작합니다.',
    attackTypes: ['Simple traversal (../)', 'URL-encoded traversal (%2e%2e)', 'Double-encoding', 'Null byte injection'],
    impactDescription: 'Read sensitive files (/etc/passwd, config files), source code disclosure, potential write access.',
    preventionTechniques: [
      'Use path.resolve() and verify the result starts with the expected base directory',
      'Use chroot or containerized file system',
      'Whitelist allowed filenames/extensions',
      'Strip or reject path traversal sequences',
    ],
    preventionTechniquesKo: [
      'path.resolve() 사용 후 결과가 예상 기본 디렉터리로 시작하는지 검증',
      'chroot 또는 컨테이너화된 파일 시스템 사용',
      '허용된 파일명/확장자 화이트리스트 적용',
      '경로 탐색 시퀀스 제거 또는 거부',
    ],
    secureCodeExample: `// Safe: Resolve and validate path
import path from 'path';
const BASE_DIR = '/app/uploads';
const resolved = path.resolve(BASE_DIR, userFilename);
if (!resolved.startsWith(BASE_DIR)) throw new Error('Path traversal blocked');`,
    commonMistakes: ['Using path.join() without validation', 'Only stripping ../ once (double-encoded bypass)', 'Allowing absolute paths in user input'],
    commonMistakesKo: ['검증 없이 path.join() 사용', '../를 한 번만 제거 (이중 인코딩 우회)', '사용자 입력에 절대 경로 허용'],
    portswiggerUrl: 'https://portswigger.net/web-security/file-path-traversal',
  },
  {
    category: 'authentication',
    cweIds: ['CWE-287', 'CWE-306', 'CWE-798'],
    title: 'Authentication Vulnerabilities',
    titleKo: '인증 취약점',
    attackMechanism: 'Attacker exploits weak authentication mechanisms to gain unauthorized access via brute force, credential stuffing, or session manipulation.',
    attackMechanismKo: '무차별 대입, 크리덴셜 스터핑, 세션 조작을 통해 약한 인증 메커니즘을 악용하여 무단 접근합니다.',
    attackTypes: ['Brute force', 'Credential stuffing', 'Session fixation', 'Password reset poisoning', 'MFA bypass'],
    impactDescription: 'Account takeover, unauthorized access to protected resources, privilege escalation.',
    preventionTechniques: [
      'Use bcrypt/scrypt/argon2 for password hashing (never MD5/SHA)',
      'Implement account lockout after failed attempts',
      'Enforce MFA for sensitive accounts',
      'Use secure session management (HttpOnly, Secure, SameSite cookies)',
      'Implement rate limiting on login endpoints',
    ],
    preventionTechniquesKo: [
      '비밀번호 해싱에 bcrypt/scrypt/argon2 사용 (MD5/SHA 금지)',
      '실패 횟수 초과 시 계정 잠금 구현',
      '민감한 계정에 MFA 적용',
      '안전한 세션 관리 (HttpOnly, Secure, SameSite 쿠키)',
      '로그인 엔드포인트에 레이트 리미팅 구현',
    ],
    secureCodeExample: `// Secure password hashing
import bcrypt from 'bcrypt';
const SALT_ROUNDS = 12;
const hash = await bcrypt.hash(password, SALT_ROUNDS);
const isValid = await bcrypt.compare(inputPassword, storedHash);`,
    commonMistakes: ['Using MD5/SHA for passwords', 'No account lockout mechanism', 'Session ID in URL', 'Verbose login error messages (username enumeration)'],
    commonMistakesKo: ['비밀번호에 MD5/SHA 사용', '계정 잠금 메커니즘 없음', 'URL에 세션 ID', '상세한 로그인 에러 메시지 (사용자명 열거)'],
    portswiggerUrl: 'https://portswigger.net/web-security/authentication',
  },
  {
    category: 'access-control',
    cweIds: ['CWE-639', 'CWE-284', 'CWE-862'],
    title: 'Broken Access Control',
    titleKo: '취약한 접근 제어',
    attackMechanism: 'Attacker accesses resources/functions beyond their permissions by manipulating parameters, URLs, or API endpoints.',
    attackMechanismKo: '파라미터, URL, API 엔드포인트를 조작하여 권한을 넘어서는 리소스/기능에 접근합니다.',
    attackTypes: ['IDOR (Insecure Direct Object Reference)', 'Forced browsing', 'Privilege escalation', 'Parameter tampering', 'Missing function-level access control'],
    impactDescription: 'Unauthorized data access/modification, privilege escalation, data breach.',
    preventionTechniques: [
      'Verify resource ownership on every request (not just authentication)',
      'Use RBAC or ABAC for authorization',
      'Deny by default - explicitly grant access',
      'Use indirect references (UUIDs) instead of sequential IDs',
      'Implement server-side access control checks (never client-side only)',
    ],
    preventionTechniquesKo: [
      '모든 요청에서 리소스 소유권 검증 (인증만이 아닌)',
      'RBAC 또는 ABAC 인가 모델 사용',
      '기본 거부 - 명시적 접근 부여',
      '순차 ID 대신 간접 참조 (UUID) 사용',
      '서버 측 접근 제어 검사 구현 (클라이언트 측만 금지)',
    ],
    secureCodeExample: `// Verify resource ownership
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.userId !== req.user.id) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json(order);
});`,
    commonMistakes: ['Relying on client-side access control', 'Using sequential IDs for sensitive resources', 'Only checking authentication, not authorization', 'Inconsistent access control across endpoints'],
    commonMistakesKo: ['클라이언트 측 접근 제어에 의존', '민감한 리소스에 순차 ID 사용', '인증만 확인하고 인가 미확인', '엔드포인트 간 일관성 없는 접근 제어'],
    portswiggerUrl: 'https://portswigger.net/web-security/access-control',
  },
  {
    category: 'file-upload',
    cweIds: ['CWE-434'],
    title: 'File Upload Vulnerabilities',
    titleKo: '파일 업로드 취약점',
    attackMechanism: 'Attacker uploads malicious files (web shells, malware) by bypassing insufficient file type validation.',
    attackMechanismKo: '불충분한 파일 타입 검증을 우회하여 악성 파일(웹쉘, 멀웨어)을 업로드합니다.',
    attackTypes: ['Web shell upload', 'Content-Type manipulation', 'Double extension (.php.jpg)', 'Null byte injection', 'Race condition upload'],
    impactDescription: 'Remote code execution, server compromise, malware distribution.',
    preventionTechniques: [
      'Validate file type by magic bytes (not just extension or Content-Type)',
      'Store uploads outside web root with random filenames',
      'Remove execute permissions from upload directory',
      'Set Content-Disposition: attachment for downloads',
      'Scan uploaded files with antivirus',
      'Limit file size',
    ],
    preventionTechniquesKo: [
      '매직 바이트로 파일 타입 검증 (확장자/Content-Type만 아닌)',
      '웹 루트 외부에 랜덤 파일명으로 저장',
      '업로드 디렉터리에서 실행 권한 제거',
      '다운로드 시 Content-Disposition: attachment 설정',
      '업로드 파일 안티바이러스 스캔',
      '파일 크기 제한',
    ],
    secureCodeExample: `// Secure file upload with multer
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';

const storage = multer.diskStorage({
  destination: '/var/uploads/', // outside web root
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.jpg', '.png', '.pdf'];
    if (!allowed.includes(ext)) return cb(new Error('Invalid type'));
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });`,
    commonMistakes: ['Checking only file extension', 'Storing uploads in web-accessible directory', 'Using original filename', 'No file size limit'],
    commonMistakesKo: ['파일 확장자만 검사', '웹 접근 가능한 디렉터리에 업로드 저장', '원본 파일명 사용', '파일 크기 제한 없음'],
    portswiggerUrl: 'https://portswigger.net/web-security/file-upload',
  },
  {
    category: 'jwt-attacks',
    cweIds: ['CWE-345', 'CWE-347'],
    title: 'JWT Attacks',
    titleKo: 'JWT 공격',
    attackMechanism: 'Attacker exploits JWT implementation flaws: algorithm confusion, missing verification, weak secrets, or token manipulation.',
    attackMechanismKo: 'JWT 구현 결함을 악용: 알고리즘 혼동, 검증 누락, 약한 비밀키, 토큰 조작.',
    attackTypes: ['Algorithm confusion (none/HS256 vs RS256)', 'Weak secret brute force', 'JWK injection', 'kid parameter injection', 'Token expiry bypass'],
    impactDescription: 'Authentication bypass, identity spoofing, privilege escalation.',
    preventionTechniques: [
      'Always specify algorithms in verify options: { algorithms: ["HS256"] }',
      'Use strong secrets (256+ bits of entropy)',
      'Validate all claims (exp, iss, aud)',
      'Rotate secrets periodically',
      'Use asymmetric keys (RS256/ES256) for distributed systems',
    ],
    preventionTechniquesKo: [
      '검증 옵션에 알고리즘 명시: { algorithms: ["HS256"] }',
      '강력한 비밀키 사용 (256비트 이상 엔트로피)',
      '모든 클레임 검증 (exp, iss, aud)',
      '주기적 비밀키 로테이션',
      '분산 시스템에 비대칭 키 (RS256/ES256) 사용',
    ],
    secureCodeExample: `// Secure JWT verification
import jwt from 'jsonwebtoken';
const decoded = jwt.verify(token, SECRET, {
  algorithms: ['HS256'],
  issuer: 'myapp',
  audience: 'myapp-users',
  clockTolerance: 30,
});`,
    commonMistakes: ['Not specifying algorithms in verify()', 'Using jwt.decode() for authentication', 'Short/predictable JWT secrets', 'Not validating exp claim'],
    commonMistakesKo: ['verify()에 알고리즘 미명시', '인증에 jwt.decode() 사용', '짧거나 예측 가능한 JWT 비밀키', 'exp 클레임 미검증'],
    portswiggerUrl: 'https://portswigger.net/web-security/jwt',
  },
  {
    category: 'prototype-pollution',
    cweIds: ['CWE-1321'],
    title: 'Prototype Pollution',
    titleKo: '프로토타입 오염',
    attackMechanism: 'Attacker modifies Object.prototype via unsafe object merge/set operations, injecting properties into all objects.',
    attackMechanismKo: '안전하지 않은 객체 병합/설정 연산을 통해 Object.prototype을 수정하여 모든 객체에 속성을 주입합니다.',
    attackTypes: ['Server-side prototype pollution', 'Client-side prototype pollution', 'Prototype pollution to RCE', 'Prototype pollution to XSS'],
    impactDescription: 'DoS, privilege escalation, RCE (via gadget chains), XSS, authentication bypass.',
    preventionTechniques: [
      'Use Object.create(null) for dictionary-like objects',
      'Validate input with schema (zod/joi) before merge',
      'Filter __proto__, constructor, prototype keys',
      'Use Map instead of plain objects for user data',
      'Object.freeze(Object.prototype) in critical contexts',
    ],
    preventionTechniquesKo: [
      '딕셔너리 객체에 Object.create(null) 사용',
      '병합 전 zod/joi 스키마로 입력 검증',
      '__proto__, constructor, prototype 키 필터링',
      '사용자 데이터에 일반 객체 대신 Map 사용',
      '중요 컨텍스트에서 Object.freeze(Object.prototype)',
    ],
    secureCodeExample: `// Safe merge with key filtering
function safeMerge(target, source) {
  const blocked = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(source)) {
    if (blocked.has(key)) continue;
    target[key] = source[key];
  }
  return target;
}`,
    commonMistakes: ['Using _.merge with user input', 'Recursive merge without key filtering', 'JSON.parse of user input without validation', 'Using bracket notation with user-controlled keys'],
    commonMistakesKo: ['사용자 입력으로 _.merge 사용', '키 필터링 없는 재귀 병합', '검증 없는 사용자 입력 JSON.parse', '사용자 제어 키로 브라켓 표기법 사용'],
    portswiggerUrl: 'https://portswigger.net/web-security/prototype-pollution',
  },
  {
    category: 'race-conditions',
    cweIds: ['CWE-362'],
    title: 'Race Conditions',
    titleKo: '레이스 컨디션',
    attackMechanism: 'Attacker exploits time-of-check-to-time-of-use (TOCTOU) gaps by sending concurrent requests that interfere with each other.',
    attackMechanismKo: '동시 요청을 보내 검사 시점과 사용 시점(TOCTOU) 사이의 간격을 악용합니다.',
    attackTypes: ['Limit overrun (coupon/balance)', 'Multi-endpoint race conditions', 'Single-endpoint race conditions', 'Time-sensitive partial construction'],
    impactDescription: 'Double spending, coupon abuse, inventory manipulation, authentication bypass.',
    preventionTechniques: [
      'Use database transactions with appropriate isolation levels',
      'Implement optimistic locking (version columns)',
      'Use atomic operations (UPDATE ... SET balance = balance - $1 WHERE balance >= $1)',
      'Apply distributed locks for cross-service operations',
      'Use idempotency keys for payment operations',
    ],
    preventionTechniquesKo: [
      '적절한 격리 수준의 DB 트랜잭션 사용',
      '낙관적 잠금 (버전 컬럼) 구현',
      '원자적 연산 사용 (UPDATE ... SET balance = balance - $1 WHERE balance >= $1)',
      '크로스 서비스 작업에 분산 락 적용',
      '결제 작업에 멱등성 키 사용',
    ],
    secureCodeExample: `// Atomic balance update
const result = await db.query(
  'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance',
  [amount, accountId]
);
if (result.rowCount === 0) throw new Error('Insufficient balance');`,
    commonMistakes: ['Read-then-write without transaction', 'No locking on shared resources', 'Trusting client-side deduplication', 'Missing idempotency in payment flows'],
    commonMistakesKo: ['트랜잭션 없이 읽기 후 쓰기', '공유 리소스에 잠금 없음', '클라이언트 측 중복 제거 신뢰', '결제 흐름에 멱등성 누락'],
    portswiggerUrl: 'https://portswigger.net/web-security/race-conditions',
  },
  {
    category: 'nosql-injection',
    cweIds: ['CWE-943'],
    title: 'NoSQL Injection',
    titleKo: 'NoSQL 인젝션',
    attackMechanism: 'Attacker injects NoSQL query operators ($gt, $ne, $regex) via user input to bypass authentication or extract data.',
    attackMechanismKo: '사용자 입력을 통해 NoSQL 쿼리 연산자($gt, $ne, $regex)를 주입하여 인증을 우회하거나 데이터를 추출합니다.',
    attackTypes: ['Operator injection ($ne, $gt)', 'JavaScript injection ($where)', 'Regex-based extraction', 'Timing-based extraction'],
    impactDescription: 'Authentication bypass, data exfiltration, DoS via expensive queries.',
    preventionTechniques: [
      'Validate input types strictly (reject objects when string expected)',
      'Use mongoose schema validation with strict mode',
      'Sanitize user input with mongo-sanitize',
      'Avoid $where and mapReduce with user input',
      'Use parameterized aggregation pipelines',
    ],
    preventionTechniquesKo: [
      '입력 타입 엄격히 검증 (문자열 예상 시 객체 거부)',
      'strict 모드의 mongoose 스키마 검증 사용',
      'mongo-sanitize로 사용자 입력 새니타이즈',
      '사용자 입력으로 $where, mapReduce 사용 금지',
      '파라미터화된 집계 파이프라인 사용',
    ],
    secureCodeExample: `// Safe MongoDB query with type validation
const username = typeof req.body.username === 'string' ? req.body.username : '';
const password = typeof req.body.password === 'string' ? req.body.password : '';
const user = await User.findOne({ username, password: await bcrypt.hash(password, salt) });`,
    commonMistakes: ['Passing req.body directly to query', 'Not validating input types', 'Using $where with user input', 'Trusting Express bodyParser type coercion'],
    commonMistakesKo: ['req.body를 쿼리에 직접 전달', '입력 타입 미검증', '사용자 입력으로 $where 사용', 'Express bodyParser 타입 변환 신뢰'],
    portswiggerUrl: 'https://portswigger.net/web-security/nosql-injection',
  },
  {
    category: 'request-smuggling',
    cweIds: ['CWE-444'],
    title: 'HTTP Request Smuggling',
    titleKo: 'HTTP 요청 스머글링',
    attackMechanism: 'Attacker exploits discrepancies between how front-end and back-end servers parse HTTP request boundaries (Content-Length vs Transfer-Encoding).',
    attackMechanismKo: '프론트엔드와 백엔드 서버 간 HTTP 요청 경계 파싱 차이(Content-Length vs Transfer-Encoding)를 악용합니다.',
    attackTypes: ['CL.TE smuggling', 'TE.CL smuggling', 'TE.TE (obfuscated TE)', 'H2.CL smuggling (HTTP/2 downgrade)'],
    impactDescription: 'Bypass security controls, access other users\' requests, cache poisoning, credential hijacking.',
    preventionTechniques: [
      'Use HTTP/2 end-to-end (no downgrade to HTTP/1.1)',
      'Configure front-end server to normalize ambiguous requests',
      'Reject requests with both Content-Length and Transfer-Encoding',
      'Use the same web server software for all layers',
    ],
    preventionTechniquesKo: [
      'HTTP/2를 엔드투엔드로 사용 (HTTP/1.1 다운그레이드 없음)',
      '프론트엔드 서버에서 모호한 요청 정규화 설정',
      'Content-Length과 Transfer-Encoding 동시 포함 요청 거부',
      '모든 계층에 동일한 웹 서버 소프트웨어 사용',
    ],
    secureCodeExample: `// Nginx: reject ambiguous requests
proxy_set_header Transfer-Encoding "";
proxy_http_version 1.1;
# Use HTTP/2 where possible`,
    commonMistakes: ['Mixed HTTP/1.1 and HTTP/2 in reverse proxy chain', 'Not normalizing Transfer-Encoding header', 'Allowing keep-alive with inconsistent parsers'],
    commonMistakesKo: ['리버스 프록시 체인에서 HTTP/1.1과 HTTP/2 혼용', 'Transfer-Encoding 헤더 정규화 미적용', '일관성 없는 파서에서 keep-alive 허용'],
    portswiggerUrl: 'https://portswigger.net/web-security/request-smuggling',
  },
];

export function getKnowledgeByCwe(cweId: string): PortSwiggerKnowledge | undefined {
  return PORTSWIGGER_KB.find((k) => k.cweIds.includes(cweId));
}

export function getAllCategories(): string[] {
  return PORTSWIGGER_KB.map((k) => k.category);
}

export function getAllKnowledge(): PortSwiggerKnowledge[] {
  return [...PORTSWIGGER_KB];
}

export function getKnowledgeByCategory(category: string): PortSwiggerKnowledge | undefined {
  return PORTSWIGGER_KB.find((k) => k.category === category);
}

export function findKnowledgeForCweIds(cweIds: string[]): PortSwiggerKnowledge[] {
  const seen = new Set<string>();
  const results: PortSwiggerKnowledge[] = [];
  for (const cweId of cweIds) {
    const kb = PORTSWIGGER_KB.find((k) => k.cweIds.includes(cweId));
    if (kb && !seen.has(kb.category)) {
      seen.add(kb.category);
      results.push(kb);
    }
  }
  return results;
}

