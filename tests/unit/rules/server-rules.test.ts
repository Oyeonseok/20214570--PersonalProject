import { describe, it, expect } from 'vitest';
import { scanCode } from '../../../src/engine/scanner.js';
import { serverRules } from '../../../src/rules/server-rules.js';

describe('Server Security Rules', () => {
  it('has 14 rules loaded', () => {
    expect(serverRules.length).toBe(14);
  });

  it('every rule has unique ID starting with SCG-SRV', () => {
    const ids = serverRules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^SCG-SRV-/);
    }
  });
});

describe('Prototype Pollution detection', () => {
  it('detects Object.assign with req.body', () => {
    const code = 'const merged = Object.assign({}, req.body);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-1321')).toBe(true);
  });

  it('detects _.merge with user input', () => {
    const code = 'const result = _.merge(config, req.body);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-1321')).toBe(true);
  });

  it('does not flag when schema validation present', () => {
    const code = 'const validated = schema.parse(req.body); Object.assign({}, validated);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.filter((v) => v.cweId === 'CWE-1321').length).toBe(0);
  });
});

describe('XXE detection', () => {
  it('detects xml2js parsing', () => {
    const code = 'const parser = new xml2js.Parser(); parser.parseString(userXml);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-611')).toBe(true);
  });

  it('detects Python lxml.etree', () => {
    const code = 'from lxml import etree\ntree = lxml.etree.parse(user_input)';
    const result = scanCode(code, { language: 'python' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-611')).toBe(true);
  });

  it('detects Java DocumentBuilderFactory', () => {
    const code = 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();';
    const result = scanCode(code, { language: 'java' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-611')).toBe(true);
  });
});

describe('File Upload detection', () => {
  it('detects multer without fileFilter', () => {
    const code = "const upload = multer({ dest: 'uploads/' });";
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-434')).toBe(true);
  });

  it('does not flag multer with fileFilter', () => {
    const code = "const upload = multer({ dest: 'uploads/', fileFilter: validateType, limits: { fileSize: 5e6 } });";
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.filter((v) => v.cweId === 'CWE-434').length).toBe(0);
  });
});

describe('Command Injection via shell:true', () => {
  it('detects spawn with shell: true', () => {
    const code = "const proc = spawn('ls', args, { shell: true });";
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-CMD-001')).toBe(true);
  });

  it('detects Python subprocess with shell=True', () => {
    const code = 'subprocess.Popen(cmd, shell=True)';
    const result = scanCode(code, { language: 'python' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-CMD-001')).toBe(true);
  });
});

describe('JWT Algorithm Confusion', () => {
  it('detects jwt.decode without verify', () => {
    const code = 'const payload = jwt.decode(token);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-JWT-001')).toBe(true);
  });

  it('detects algorithm: none', () => {
    const code = "jwt.sign(payload, secret, { algorithm: 'none' });";
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-JWT-001')).toBe(true);
  });
});

describe('SSRF Cloud Metadata', () => {
  it('detects fetch with user-controlled URL', () => {
    const code = 'const resp = await fetch(req.body.url);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-918')).toBe(true);
  });

  it('detects cloud metadata IP literal', () => {
    const code = 'const resp = await fetch("http://169.254.169.254/latest/meta-data/");';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-918')).toBe(true);
  });
});

describe('NoSQL Injection', () => {
  it('detects $where with user input', () => {
    const code = 'db.users.find({ $where: req.body.filter });';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-943')).toBe(true);
  });

  it('detects .find(req.body)', () => {
    const code = 'const result = await User.find(req.body);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.cweId === 'CWE-943')).toBe(true);
  });
});

describe('Error Exposure', () => {
  it('detects res.json(err)', () => {
    const code = 'app.use((err, req, res, next) => { res.json(err); });';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-ERR-001')).toBe(true);
  });

  it('does not flag res.json({ message: err.message })', () => {
    const code = 'res.json({ message: err.message });';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.filter((v) => v.ruleId === 'SCG-SRV-ERR-001').length).toBe(0);
  });
});

describe('Missing Body Size Limit', () => {
  it('detects express.json() without limit', () => {
    const code = 'app.use(express.json());';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-DOS-001')).toBe(true);
  });
});

describe('IDOR detection', () => {
  it('detects findById without ownership check', () => {
    const code = 'const post = await Post.findById(req.params.id);';
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-IDOR-001')).toBe(true);
  });
});

describe('Open Redirect', () => {
  it('detects res.redirect with user input', () => {
    const code = "res.redirect(req.query.next);";
    const result = scanCode(code, { language: 'javascript' });
    expect(result.vulnerabilities.some((v) => v.ruleId === 'SCG-SRV-REDIR-001')).toBe(true);
  });
});
