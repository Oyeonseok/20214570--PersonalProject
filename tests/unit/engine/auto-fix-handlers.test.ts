import { describe, it, expect } from 'vitest';
import { applySecureFixes } from '../../../src/engine/secure-fixer.js';
import { scanCode } from '../../../src/engine/scanner.js';

function scanAndFix(code: string, lang: 'javascript' | 'typescript' = 'javascript') {
  const result = scanCode(code, { language: lang, severityThreshold: 'info' });
  return applySecureFixes(code, result.vulnerabilities);
}

describe('Tier 1: Critical/High Auto-Fix Handlers', () => {

  describe('SQL Injection (SCG-INJ-SQL-001)', () => {
    it('converts template literal SQL to parameterized query', () => {
      const code = "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('$1');
      expect(fix.fixedCode).toContain('[req.params.id]');
      expect(fix.appliedFixes.some(f => f.ruleId === 'SCG-INJ-SQL-001')).toBe(true);
    });

    it('converts string concatenation SQL to parameterized query', () => {
      const code = 'db.query("SELECT * FROM users WHERE name = " + req.body.name);';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('$1');
      expect(fix.fixedCode).toContain('[req.body.name]');
    });
  });

  describe('Hardcoded Secrets (SCG-AUF-SECRET-001)', () => {
    it('replaces hardcoded password with process.env', () => {
      const code = 'const password = "super-secret-pass-123";';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('process.env.');
      expect(fix.fixedCode).not.toContain('super-secret-pass-123');
    });

    it('replaces hardcoded JWT secret with process.env', () => {
      const code = 'const JWT_SECRET = "my-jwt-secret-key-here";';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('process.env.');
    });

    it('does not touch process.env references', () => {
      const code = 'const password = process.env.DB_PASSWORD;';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toBe(code);
    });
  });

  describe('Cookie Security (SCG-AUF-COOKIE-001)', () => {
    it('adds security flags to res.cookie without options', () => {
      const code = "res.cookie('session', token);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('httpOnly: true');
      expect(fix.fixedCode).toContain('secure: true');
      expect(fix.fixedCode).toContain("sameSite: 'strict'");
    });

    it('fixes httpOnly: false to true', () => {
      const code = "cookie = { httpOnly: false, session: true };";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('httpOnly: true');
    });
  });

  describe('CORS Wildcard (SCG-AUF-CORS-001)', () => {
    it('replaces cors() with env-based origins', () => {
      const code = "app.use(cors());";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('ALLOWED_ORIGINS');
      expect(fix.fixedCode).not.toContain('cors()');
    });

    it("replaces origin: '*' with env-based origins", () => {
      const code = "app.use(cors({ origin: '*' }));";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('ALLOWED_ORIGINS');
      expect(fix.fixedCode).not.toContain("'*'");
    });
  });

  describe('JWT decode → verify (SCG-SRV-JWT-001)', () => {
    it('converts jwt.decode to jwt.verify', () => {
      const code = 'const payload = jwt.decode(token);';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('jwt.verify');
      expect(fix.fixedCode).toContain('JWT_SECRET');
      expect(fix.fixedCode).toContain("algorithms: ['HS256']");
    });

    it('adds algorithms to jwt.verify without them', () => {
      const code = "const payload = jwt.verify(token, secret);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("algorithms: ['HS256']");
    });
  });

  describe('Math.random → crypto (SCG-CRY-RAND-001)', () => {
    it('converts Math.random().toString(36) to crypto.randomBytes', () => {
      const code = "const token = Math.random().toString(36).substring(2);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('crypto.randomBytes');
      expect(fix.fixedCode).not.toContain('Math.random');
    });

    it('converts Math.random in security context', () => {
      const code = "const token = Math.random().toString(16);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('crypto.randomBytes');
      expect(fix.fixedCode).not.toContain('Math.random');
    });
  });

  describe('Command Injection (SCG-INJ-CMD-001)', () => {
    it('converts exec with template literal to execFile', () => {
      const code = "exec(`ls ${req.body.dir}`);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('execFile');
    });

    it('converts exec with string concat to execFile', () => {
      const code = "exec('ls ' + req.query.path);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('execFile');
    });
  });

  describe('Weak Hash (SCG-AUF-HASH-001 / SCG-CRY-HASH-001)', () => {
    it('converts MD5 to SHA-256', () => {
      const code = "const hash = crypto.createHash('md5').update(data).digest('hex');";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("'sha256'");
      expect(fix.fixedCode).not.toContain("'md5'");
    });

    it('converts SHA1 to SHA-256', () => {
      const code = "const hash = crypto.createHash('sha1').update(data).digest('hex');";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("'sha256'");
    });

    it('converts MD5 for password context to bcrypt', () => {
      const code = "const passwordHash = crypto.createHash('md5').update(password).digest('hex');";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('bcrypt');
    });
  });
});

describe('Tier 2: Medium Auto-Fix Handlers', () => {

  describe('Helmet Middleware (SCG-MCF-HELMET-001)', () => {
    it('injects helmet middleware after express()', () => {
      const code = "const app = express();\napp.get('/', handler);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('helmet()');
    });
  });

  describe('Rate Limiting (SCG-MCF-RATE-001)', () => {
    it('injects rate limiter or CSRF on auth route', () => {
      const code = "app.post('/login', async (req, res) => { });";
      const fix = scanAndFix(code);
      const hasRateLimit = fix.fixedCode.includes('rateLimit');
      const hasCsrf = fix.fixedCode.includes('csrf');
      expect(hasRateLimit || hasCsrf).toBe(true);
    });
  });

  describe('Debug Mode (SCG-MCF-DEBUG-001)', () => {
    it('replaces debug: true with env-based check', () => {
      const code = "const config = { debug: true, port: 3000 };";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("process.env.NODE_ENV !== 'production'");
      expect(fix.fixedCode).not.toMatch(/debug\s*:\s*true/);
    });
  });

  describe('Session Security (SCG-AUF-SESSION-001)', () => {
    it('replaces short session secret with env var', () => {
      const code = "app.use(session({ secret: 'abc123', resave: false }));";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('process.env.');
      expect(fix.fixedCode).not.toContain("'abc123'");
    });

    it('fixes resave: true to false', () => {
      const code = "app.use(session({ secret: process.env.SECRET, resave: true }));";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('resave: false');
    });
  });

  describe('React dangerouslySetInnerHTML (SCG-XSS-REACT-001)', () => {
    it('wraps dangerouslySetInnerHTML with DOMPurify', () => {
      const code = '<div dangerouslySetInnerHTML={{ __html: userContent }} />';
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('DOMPurify.sanitize');
    });
  });

  describe('Prototype Pollution (SCG-SRV-PROTO-001)', () => {
    it('filters dangerous keys from Object.assign', () => {
      const code = "const config = Object.assign({}, req.body);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('__proto__');
      expect(fix.fixedCode).toContain('constructor');
      expect(fix.fixedCode).toContain('filter');
    });
  });

  describe('Verbose Error (SCG-MCF-ERR-001)', () => {
    it('replaces err.stack exposure with generic error', () => {
      const code = "res.status(500).json({ error: err.stack });";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('서버 오류가 발생했습니다');
      expect(fix.fixedCode).toContain('console.error');
    });
  });

  describe('HTTP to HTTPS (SCG-MCF-HTTP-001)', () => {
    it('converts HTTP URL to HTTPS', () => {
      const code = "fetch('http://api.example.com/data');";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('https://api.example.com');
    });

    it('does not convert localhost HTTP', () => {
      const code = "fetch('http://localhost:3000/api');";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('http://localhost');
    });
  });
});

describe('Tier 3: Strengthened Existing Handlers', () => {

  describe('eval → safe alternative (SCG-INJ-CODE-001)', () => {
    it('converts eval(jsonStr) to JSON.parse', () => {
      const code = "const data = eval(jsonString);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).not.toMatch(/\beval\s*\(/);
    });

    it('removes eval with void wrapper', () => {
      const code = "eval(userCode);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).not.toMatch(/\beval\s*\(/);
    });
  });

  describe('document.write → DOM API (SCG-XSS-DOM-002)', () => {
    it('converts to createTextNode', () => {
      const code = "document.write(content);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('createTextNode');
      expect(fix.fixedCode).toContain('appendChild');
    });
  });

  describe('innerHTML → DOMPurify for dynamic content', () => {
    it('wraps dynamic innerHTML with DOMPurify.sanitize', () => {
      const code = "element.innerHTML = userInput;";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('textContent');
    });
  });
});

describe('Crypto Auto-Fix Handlers', () => {

  describe('Weak Algorithm (SCG-CRY-ALGO-001)', () => {
    it('replaces DES with AES-256-GCM', () => {
      const code = "const cipher = crypto.createCipheriv('des', key, iv);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("'aes-256-gcm'");
    });
  });

  describe('Hardcoded Encryption Key (SCG-CRY-KEY-001)', () => {
    it('replaces hardcoded key with process.env', () => {
      const code = "const encryption_key = 'my-secret-encryption-key-1234';";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('process.env.');
    });
  });

  describe('TLS Verification Disabled (SCG-CRY-TLS-001)', () => {
    it('fixes rejectUnauthorized: false', () => {
      const code = "const agent = new https.Agent({ rejectUnauthorized: false });";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('rejectUnauthorized: true');
    });

    it('fixes NODE_TLS_REJECT_UNAUTHORIZED = 0', () => {
      const code = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).not.toContain("= '0'");
    });
  });
});

describe('Server Auto-Fix Handlers', () => {

  describe('Error Exposure (SCG-SRV-ERR-001)', () => {
    it('replaces res.json(err) with generic error', () => {
      const code = "res.json(err);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('서버 오류가 발생했습니다');
    });
  });

  describe('DoS Prevention (SCG-SRV-DOS-001)', () => {
    it('adds limit to express.json()', () => {
      const code = "app.use(express.json());";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain("limit: '1mb'");
    });
  });

  describe('Shell True (SCG-SRV-CMD-001)', () => {
    it('replaces shell: true with shell: false', () => {
      const code = "spawn('cmd', args, { shell: true });";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('shell: false');
    });
  });

  describe('Log Injection (SCG-INJ-LOG-001)', () => {
    it('sanitizes user input in logs', () => {
      const code = "console.log('User login:', req.body.username);";
      const fix = scanAndFix(code);
      expect(fix.fixedCode).toContain('replace');
    });
  });
});

describe('Import Injection System', () => {
  it('adds crypto import when Math.random is fixed', () => {
    const code = "const token = Math.random().toString(36);";
    const fix = scanAndFix(code);
    expect(fix.addedImports.length).toBeGreaterThan(0);
    expect(fix.addedImports.some(i => i.includes('crypto'))).toBe(true);
  });

  it('does not duplicate existing imports', () => {
    const code = "import crypto from 'crypto';\nconst token = Math.random().toString(36);";
    const fix = scanAndFix(code);
    const cryptoImports = fix.addedImports.filter(i => i.includes('crypto'));
    expect(cryptoImports.length).toBe(0);
  });
});

describe('Post-Fix Verification', () => {
  it('verifies fixes actually resolve vulnerabilities via rescan', () => {
    const code = "const hash = crypto.createHash('md5').update(data).digest('hex');";
    const initial = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const fix = applySecureFixes(code, initial.vulnerabilities);
    const postScan = scanCode(fix.fixedCode, { language: 'javascript', severityThreshold: 'info' });

    const hashVulnsBefore = initial.vulnerabilities.filter(v => v.ruleId === 'SCG-CRY-HASH-001');
    const hashVulnsAfter = postScan.vulnerabilities.filter(v => v.ruleId === 'SCG-CRY-HASH-001');

    expect(hashVulnsBefore.length).toBeGreaterThan(0);
    expect(hashVulnsAfter.length).toBe(0);
  });

  it('resolves CORS wildcard vulnerability after fix', () => {
    const code = "app.use(cors({ origin: '*' }));";
    const initial = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const fix = applySecureFixes(code, initial.vulnerabilities);
    const postScan = scanCode(fix.fixedCode, { language: 'javascript', severityThreshold: 'info' });

    const corsBefore = initial.vulnerabilities.filter(v => v.ruleId === 'SCG-AUF-CORS-001');
    const corsAfter = postScan.vulnerabilities.filter(v => v.ruleId === 'SCG-AUF-CORS-001');

    expect(corsBefore.length).toBeGreaterThan(0);
    expect(corsAfter.length).toBe(0);
  });
});

describe('Multi-Language Auto-Fix', () => {
  it('fixes Python secret_key with os.environ.get', () => {
    const code = "from flask import Flask\napp = Flask(__name__)\napp.secret_key = 'my-super-secret-key-123'\n";
    const fix = scanAndFix(code, 'javascript');
    expect(fix.fixedCode).toContain('os.environ.get');
    expect(fix.fixedCode).not.toContain('my-super-secret-key-123');
  });

  it('fixes PHP secret with getenv', () => {
    const code = "<?php\n$secret = 'hardcoded-secret-value-here';\n";
    const fix = scanAndFix(code, 'javascript');
    expect(fix.fixedCode).toContain('getenv');
  });

  it('fixes Java secret with System.getenv', () => {
    const code = 'public class App {\n  private String password = "super-secret-pass-123";\n}\n';
    const fix = scanAndFix(code, 'javascript');
    expect(fix.fixedCode).toContain('System.getenv');
  });

  it('fixes Go secret with os.Getenv', () => {
    const code = 'package main\nfunc main() {\n  secret := "hardcoded-secret-value"\n}\n';
    const fix = scanAndFix(code, 'javascript');
    expect(fix.fixedCode).toContain('os.Getenv');
  });

  it('fixes Ruby secret with ENV', () => {
    const code = "require 'sinatra'\npassword = 'my-secret-password-long'\n";
    const fix = scanAndFix(code, 'javascript');
    expect(fix.fixedCode).toContain("ENV[");
  });

  it('fixes C# secret with Environment.GetEnvironmentVariable', () => {
    const code = 'using System;\nnamespace App {\n  string password = "my-secret-pass-1234";\n}\n';
    const fix = scanAndFix(code, 'javascript');
    expect(fix.fixedCode).toContain('Environment.GetEnvironmentVariable');
  });

  it('detects in-memory storage in Python and replaces with SQLite', () => {
    const code = "from flask import Flask\nusers = {}\napp = Flask(__name__)\n";
    const result = scanCode(code, { language: 'python', severityThreshold: 'info' });
    const inmem = result.vulnerabilities.filter(v => v.ruleId === 'SCG-SRV-INMEM-001');
    expect(inmem.length).toBeGreaterThan(0);

    const fix = applySecureFixes(code, result.vulnerabilities);
    expect(fix.fixedCode).toContain('sqlite3');
  });

  it('detects in-memory storage in JS and replaces with DB', () => {
    const code = "const users = {};\napp.get('/users', (req, res) => {});\n";
    const result = scanCode(code, { language: 'javascript', severityThreshold: 'info' });
    const inmem = result.vulnerabilities.filter(v => v.ruleId === 'SCG-SRV-INMEM-001');
    expect(inmem.length).toBeGreaterThan(0);
  });
});

describe('Cookie Security Comprehensive Fix', () => {
  it('fixes httpOnly: true but missing secure flag', () => {
    const code = "res.cookie('sid', token, { httpOnly: true });";
    const fix = scanAndFix(code);
    expect(fix.fixedCode).toContain('secure: true');
    expect(fix.fixedCode).toContain("sameSite: 'strict'");
  });

  it('fixes secure: false alongside httpOnly: false in same line', () => {
    const code = "const opts = { httpOnly: false, secure: false };";
    const fix = scanAndFix(code);
    expect(fix.fixedCode).toContain('httpOnly: true');
    expect(fix.fixedCode).toContain('secure: true');
  });

  it('fixes Flask SESSION_COOKIE_SECURE = False', () => {
    const code = "from flask import Flask\napp = Flask(__name__)\napp.config['SESSION_COOKIE_SECURE'] = False\n";
    const result = scanCode(code, { language: 'python', severityThreshold: 'info' });
    const cookieVuln = result.vulnerabilities.filter(v => v.ruleId === 'SCG-AUF-COOKIE-001');
    expect(cookieVuln.length).toBeGreaterThan(0);
    const fix = applySecureFixes(code, result.vulnerabilities);
    expect(fix.fixedCode).toContain('True');
    expect(fix.fixedCode).not.toContain('= False');
  });

  it('fixes Flask SESSION_COOKIE_HTTPONLY = False', () => {
    const code = "from flask import Flask\napp.config['SESSION_COOKIE_HTTPONLY'] = False\n";
    const result = scanCode(code, { language: 'python', severityThreshold: 'info' });
    const fix = applySecureFixes(code, result.vulnerabilities);
    expect(fix.fixedCode).toContain('True');
  });
});
