import type { Vulnerability, Severity } from '../types/index.js';

export interface AppliedFix {
  line: number;
  ruleId: string;
  severity: Severity;
  description: string;
  before: string;
  after: string;
}

export interface ManualFix {
  line: number;
  ruleId: string;
  severity: Severity;
  description: string;
  suggestion: string;
  matchedCode: string;
}

export interface FixResult {
  fixedCode: string;
  appliedFixes: AppliedFix[];
  manualFixes: ManualFix[];
  injectedHeaders: string[];
  serverGuides: string[];
  addedImports: string[];
}

/**
 * 취약점이 발견된 코드를 자동 수정하고, 자동 수정이 불가능한 항목은 수동 가이드를 반환
 */
export function applySecureFixes(code: string, vulnerabilities: Vulnerability[]): FixResult {
  const appliedFixes: AppliedFix[] = [];
  const manualFixes: ManualFix[] = [];
  const injectedHeaders: string[] = [];
  const serverGuides: string[] = [];
  const addedImports: string[] = [];
  const pendingImports = new Set<string>();

  let fixedCode = code;
  const isHTML = /<html|<!DOCTYPE/i.test(code);

  // Phase 1: 라인별 자동 수정 (원본 라인 번호 기준, 역순 처리)
  const sortedVulns = [...vulnerabilities].sort((a, b) => b.location.startLine - a.location.startLine);

  for (const vuln of sortedVulns) {
    const result = tryAutoFix(fixedCode, vuln);
    if (result) {
      fixedCode = result.code;
      appliedFixes.push({
        line: vuln.location.startLine,
        ruleId: vuln.ruleId,
        severity: vuln.severity,
        description: result.description,
        before: result.before,
        after: result.after,
      });
      if (result.imports) {
        for (const imp of result.imports) pendingImports.add(imp);
      }
    } else {
      manualFixes.push({
        line: vuln.location.startLine,
        ruleId: vuln.ruleId,
        severity: vuln.severity,
        description: vuln.descriptionKo,
        suggestion: vuln.remediation.descriptionKo,
        matchedCode: vuln.matchedCode,
      });
    }
  }

  // Phase 2: HTML 공통 보안 강화
  if (isHTML) {
    fixedCode = hardenHTML(fixedCode, appliedFixes);
  }

  // Phase 3: HTML 보안 헤더 주입 (라인 수정 완료 후 마지막에 삽입)
  if (isHTML) {
    fixedCode = injectSecurityHeaders(fixedCode, injectedHeaders);
  }

  // Phase 4: Import 자동 주입 (non-HTML 코드)
  if (!isHTML && pendingImports.size > 0) {
    fixedCode = injectImports(fixedCode, pendingImports, addedImports);
  }

  // Phase 5: 서버 사이드 필수 구현 가이드 생성
  if (isHTML && injectedHeaders.length > 0) {
    serverGuides.push(buildServerHeaderGuide(injectedHeaders));
  }
  if (/<form\b/i.test(code) && /csrf/i.test(fixedCode)) {
    serverGuides.push(buildCsrfServerGuide());
  }
  if (/(?:login|signin|auth)/i.test(code) && /rateLimit|loginAttempts|MAX_ATTEMPTS/i.test(code)) {
    serverGuides.push(buildRateLimitServerGuide());
  }

  appliedFixes.sort((a, b) => a.line - b.line);
  manualFixes.sort((a, b) => a.line - b.line);

  return { fixedCode, appliedFixes, manualFixes, injectedHeaders, serverGuides, addedImports };
}

// ─── HTML 보안 헤더 주입 ───

const SECURITY_HEADERS: Array<{ check: RegExp; tag: string; name: string }> = [
  {
    check: /Content-Security-Policy/i,
    tag: `  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';">`,
    name: 'Content-Security-Policy',
  },
  {
    check: /X-Frame-Options/i,
    tag: `  <meta http-equiv="X-Frame-Options" content="DENY">`,
    name: 'X-Frame-Options (클릭재킹 방지)',
  },
  {
    check: /X-Content-Type-Options/i,
    tag: `  <meta http-equiv="X-Content-Type-Options" content="nosniff">`,
    name: 'X-Content-Type-Options',
  },
  {
    check: /Referrer-Policy/i,
    tag: `  <meta name="referrer" content="strict-origin-when-cross-origin">`,
    name: 'Referrer-Policy',
  },
];

function injectSecurityHeaders(code: string, injectedHeaders: string[]): string {
  if (!/<head/i.test(code)) return code;

  const headersToInject: string[] = [];

  for (const header of SECURITY_HEADERS) {
    if (!header.check.test(code)) {
      headersToInject.push(header.tag);
      injectedHeaders.push(header.name);
    }
  }

  if (headersToInject.length === 0) return code;

  const headerBlock = `\n  <!-- [보안] 자동 주입된 보안 헤더 -->\n${headersToInject.join('\n')}\n`;

  return code.replace(/(<head[^>]*>)/i, `$1${headerBlock}`);
}

// ─── 자동 수정 엔진 ───

interface AutoFixResult {
  code: string;
  description: string;
  before: string;
  after: string;
  imports?: string[];
}

type FixHandler = (code: string, vuln: Vulnerability) => AutoFixResult | null;

// ─── Import 자동 주입 ───

function injectImports(code: string, pending: Set<string>, addedImports: string[]): string {
  const lines = code.split('\n');
  let lastImportIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*(?:import\s|const\s+\w+\s*=\s*require\()/.test(lines[i])) {
      lastImportIdx = i;
    }
  }

  const toInject: string[] = [];
  for (const imp of pending) {
    const modName = imp.match(/from\s+['"]([^'"]+)['"]/)?.[1]
      ?? imp.match(/require\(\s*['"]([^'"]+)['"]\)/)?.[1]
      ?? imp;
    if (!code.includes(modName) || !new RegExp(`(?:import|require).*['"]${escapeRegex(modName)}['"]`).test(code)) {
      toInject.push(imp);
      addedImports.push(imp);
    }
  }

  if (toInject.length === 0) return code;

  const insertAt = lastImportIdx + 1;
  lines.splice(insertAt, 0, ...toInject);
  return lines.join('\n');
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── 라인 유틸리티 ───

function getLine(code: string, vuln: Vulnerability): { lines: string[]; lineIdx: number; line: string } | null {
  const lines = code.split('\n');
  const lineIdx = vuln.location.startLine - 1;
  if (lineIdx < 0 || lineIdx >= lines.length) return null;
  return { lines, lineIdx, line: lines[lineIdx] };
}

function buildResult(lines: string[], lineIdx: number, before: string, description: string, imports?: string[]): AutoFixResult {
  return {
    code: lines.join('\n'),
    description,
    before,
    after: lines[lineIdx].trim(),
    imports,
  };
}

const FIX_HANDLERS: Record<string, FixHandler> = {

  // ═══════════════════════════════════════════════════
  // XSS
  // ═══════════════════════════════════════════════════

  'SCG-XSS-DOM-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;
    if (isSafeInnerHtmlUsage(line)) return null;

    if (/\.innerHTML\s*=/.test(line) && /\b(?:user|input|data|param|query|body|req|response|result)\b/i.test(line)) {
      const before = line.trim();
      lines[lineIdx] = line.replace(/(\.innerHTML\s*=\s*)(.+)/, '$1DOMPurify.sanitize($2)');
      return { ...buildResult(lines, lineIdx, before, 'innerHTML = 동적값 → DOMPurify.sanitize() 래핑 (XSS 방지)'), imports: ["import DOMPurify from 'dompurify';"] };
    }

    if (/\.innerHTML\s*\+=/.test(line)) {
      const before = line.trim();
      lines[lineIdx] = line.replace(/\.innerHTML\s*\+=/, '.textContent +=');
      return buildResult(lines, lineIdx, before, 'innerHTML += → textContent += 변경 (XSS 방지)');
    }
    if (/\.outerHTML\s*=/.test(line)) {
      const before = line.trim();
      lines[lineIdx] = line.replace(/\.outerHTML\s*=/, '.textContent =');
      return buildResult(lines, lineIdx, before, 'outerHTML → textContent 변경 (XSS 방지)');
    }
    if (/\.innerHTML\s*=/.test(line)) {
      const before = line.trim();
      lines[lineIdx] = line.replace(/\.innerHTML\s*=/, '.textContent =');
      return buildResult(lines, lineIdx, before, 'innerHTML → textContent 변경 (XSS 방지)');
    }
    return null;
  },

  'SCG-XSS-DOM-002': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;
    if (!/document\.write(ln)?\s*\(/.test(line)) return null;

    const before = line.trim();
    const argMatch = line.match(/document\.write(?:ln)?\s*\((.+?)\)\s*;?/);
    if (argMatch) {
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      lines[lineIdx] = `${indent}document.body.appendChild(document.createTextNode(${argMatch[1]}));`;
      return buildResult(lines, lineIdx, before, 'document.write() → DOM API (createTextNode) 교체 (XSS 방지)');
    }
    lines[lineIdx] = line.replace(/(document\.write(?:ln)?\s*\(.+?\);?)/, '/* [보안] document.write 제거 */ // $1');
    return buildResult(lines, lineIdx, before, 'document.write() 주석 처리 (XSS 방지)');
  },

  'SCG-XSS-REACT-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;
    if (!/dangerouslySetInnerHTML/.test(line)) return null;

    const before = line.trim();
    lines[lineIdx] = line.replace(
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(.+?)\s*\}\s*\}/,
      'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize($1) }}'
    );
    return { ...buildResult(lines, lineIdx, before, 'dangerouslySetInnerHTML → DOMPurify.sanitize() 래핑 (XSS 방지)'), imports: ["import DOMPurify from 'dompurify';"] };
  },

  'SCG-XSS-DOM-004': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;
    if (!/window\.location\.href\s*=/.test(line) || /^https?:\/\//i.test(line)) return null;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';
    const varMatch = line.match(/=\s*(.+?)\s*;?\s*$/);
    if (!varMatch) return null;

    lines[lineIdx] = [
      `${indent}const __redirectUrl = new URL(${varMatch[1]}, window.location.origin);`,
      `${indent}if (__redirectUrl.origin === window.location.origin) { window.location.href = __redirectUrl.href; }`,
      `${indent}else { window.location.href = '/'; }`,
    ].join('\n');
    return buildResult(lines, lineIdx, before, '오픈 리다이렉트 방지 (동일 출처 검증 추가)');
  },

  // ═══════════════════════════════════════════════════
  // INJECTION
  // ═══════════════════════════════════════════════════

  'SCG-INJ-SQL-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    // Template literal: `SELECT ... ${var}` → 'SELECT ... $1', [var]
    const tmplMatch = line.match(/([`])(.+?)\1/);
    if (tmplMatch && /\$\{/.test(tmplMatch[2])) {
      const params: string[] = [];
      let paramIdx = 0;
      const parameterized = tmplMatch[2].replace(/\$\{(.+?)\}/g, (_, varName) => {
        paramIdx++;
        params.push(varName.trim());
        return `$${paramIdx}`;
      });
      const caller = line.match(/(\w+\.(?:query|execute|exec|run))\s*\(/)?.[1] ?? 'db.query';
      lines[lineIdx] = `${indent}${caller}('${parameterized}', [${params.join(', ')}]);`;
      return buildResult(lines, lineIdx, before, 'SQL 인젝션 방지: 템플릿 리터럴 → 파라미터화 쿼리 변환');
    }

    // String concat: "SELECT ..." + var → 'SELECT ... $1', [var]
    const concatMatch = line.match(/(['"])(.+?)\1\s*\+\s*(\w[\w.]*)/);
    if (concatMatch && /(?:SELECT|INSERT|UPDATE|DELETE)/i.test(concatMatch[2])) {
      const caller = line.match(/(\w+\.(?:query|execute|exec|run))\s*\(/)?.[1] ?? 'db.query';
      lines[lineIdx] = `${indent}${caller}('${concatMatch[2]}$1', [${concatMatch[3]}]);`;
      return buildResult(lines, lineIdx, before, 'SQL 인젝션 방지: 문자열 결합 → 파라미터화 쿼리 변환');
    }

    // Fallback: add warning + TODO
    lines[lineIdx] = `${indent}/* [보안] SQL Injection 위험 - 반드시 파라미터화 쿼리로 변환하세요 */\n${line}`;
    return buildResult(lines, lineIdx, before, 'SQL 인젝션 위험 표시 (파라미터화 쿼리 변환 필요)');
  },

  'SCG-INJ-CODE-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;
    if (!/\beval\s*\(/.test(line)) return null;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    // JSON context: eval('(' + x + ')') or eval(jsonStr) → JSON.parse
    if (/eval\s*\(\s*['"]\s*\(\s*['"]\s*\+/.test(line) || /eval\s*\(\s*(?:json|data|response|body)/i.test(line)) {
      const argMatch = line.match(/eval\s*\((.+?)\)\s*;?/);
      if (argMatch) {
        lines[lineIdx] = `${indent}JSON.parse(${argMatch[1].replace(/['"]\s*\(\s*['"]\s*\+\s*/, '').replace(/\s*\+\s*['"]\s*\)\s*['"]/, '')});`;
        return buildResult(lines, lineIdx, before, 'eval() → JSON.parse() 변환 (코드 인젝션 방지)');
      }
    }

    const argMatch = line.match(/eval\s*\((.+?)\)\s*;?/);
    if (argMatch) {
      lines[lineIdx] = `${indent}/* [보안] eval 제거됨 - 안전한 대안 사용 필요 */ void(${argMatch[1]});`;
      return buildResult(lines, lineIdx, before, 'eval() 제거 → void 처리 (코드 인젝션 방지)');
    }
    return null;
  },

  'SCG-INJ-CMD-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    // exec(`cmd ${var}`) → execFile('cmd', [var])
    const tmplExec = line.match(/(?:exec|execSync)\s*\(\s*`([^`]+)`/);
    if (tmplExec) {
      const parts = tmplExec[1].split(/\s+/);
      const cmd = parts[0].replace(/\$\{.*?\}/, '').trim() || 'command';
      const args = parts.slice(1).map(p => {
        const varMatch = p.match(/\$\{(.+?)\}/);
        return varMatch ? varMatch[1] : `'${p}'`;
      });
      lines[lineIdx] = `${indent}execFile('${cmd}', [${args.join(', ')}], (err, stdout, stderr) => { if (err) console.error(err); });`;
      return { ...buildResult(lines, lineIdx, before, 'exec(template) → execFile() + 인자 배열 변환 (명령어 인젝션 방지)'), imports: ["import { execFile } from 'child_process';"] };
    }

    // exec("cmd " + var) → execFile('cmd', [var])
    const concatExec = line.match(/(?:exec|execSync)\s*\(\s*(['"])(.+?)\1\s*\+\s*(\w[\w.]*)/);
    if (concatExec) {
      const cmdParts = concatExec[2].trim().split(/\s+/);
      const cmd = cmdParts[0] || 'command';
      lines[lineIdx] = `${indent}execFile('${cmd}', [${concatExec[3]}], (err, stdout, stderr) => { if (err) console.error(err); });`;
      return { ...buildResult(lines, lineIdx, before, 'exec(concat) → execFile() + 인자 배열 변환 (명령어 인젝션 방지)'), imports: ["import { execFile } from 'child_process';"] };
    }

    return null;
  },

  'SCG-INJ-PATH-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    const fileOpMatch = line.match(/((?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|access|sendFile)\s*\()\s*(.+?)(?:\s*,|\s*\))/);
    if (fileOpMatch) {
      const pathArg = fileOpMatch[2].trim();
      lines.splice(lineIdx, 0,
        `${indent}const __safePath = path.resolve('./uploads', ${pathArg});`,
        `${indent}if (!__safePath.startsWith(path.resolve('./uploads'))) { throw new Error('Invalid file path'); }`
      );
      return { ...buildResult(lines, lineIdx, before, '경로 탐색 방지: path.resolve() + 기본 디렉토리 검증 추가'), imports: ["import path from 'path';"] };
    }
    return null;
  },

  'SCG-INJ-LOG-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const logMatch = line.match(/((?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug))\s*\()(.+)\)/);
    if (!logMatch) return null;

    const sanitized = logMatch[2].replace(
      /(req\.(?:body|query|params|headers)(?:\.\w+)?)/g,
      "String($1).replace(/[\\n\\r\\t]/g, '_')"
    );
    lines[lineIdx] = line.replace(logMatch[2], sanitized);
    return buildResult(lines, lineIdx, before, '로그 인젝션 방지: 사용자 입력 새니타이즈 (개행문자 제거)');
  },

  'SCG-INJ-HDR-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const hdrMatch = line.match(/((?:setHeader|writeHead|res\.set|res\.header)\s*\([^,]+,\s*)(.+?)(\s*\))/);
    if (!hdrMatch) return null;

    lines[lineIdx] = line.replace(hdrMatch[2], `String(${hdrMatch[2]}).replace(/[\\r\\n]/g, '')`);
    return buildResult(lines, lineIdx, before, 'HTTP 헤더 인젝션 방지: CRLF 문자 제거');
  },

  // ═══════════════════════════════════════════════════
  // AUTH / SECRETS
  // ═══════════════════════════════════════════════════

  'SCG-AUF-SECRET-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const secretMatch = line.match(/((?:password|passwd|pwd|secret|apiKey|api_key|apiSecret|api_secret|accessToken|access_token|privateKey|private_key|JWT.SECRET|DB.PASSWORD|DATABASE.PASSWORD|PRIVATE.KEY|SECRET.KEY)\s*[:=]\s*)['"]([^'"]+)['"]/i);
    if (!secretMatch) return null;

    const varName = secretMatch[1].replace(/\s*[:=]\s*$/, '').trim();
    const envKey = varName.replace(/([a-z])([A-Z])/g, '$1_$2').replace(/[.\s-]/g, '_').toUpperCase();
    lines[lineIdx] = line.replace(/['"][^'"]{4,}['"]/, `process.env.${envKey}`);
    return buildResult(lines, lineIdx, before, `하드코딩된 시크릿 → process.env.${envKey} 환경변수 전환`);
  },

  'SCG-AUF-COOKIE-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // res.cookie('name', val) → res.cookie('name', val, { httpOnly: true, secure: true, sameSite: 'strict' })
    if (/res\.cookie\s*\(/.test(line) && !/httpOnly\s*:\s*true/.test(line)) {
      if (/res\.cookie\s*\([^)]*\{/.test(line)) {
        lines[lineIdx] = line.replace(/(\{)/, "$1 httpOnly: true, secure: true, sameSite: 'strict',");
      } else {
        lines[lineIdx] = line.replace(
          /(res\.cookie\s*\([^,]+,\s*[^,)]+)\s*\)/,
          "$1, { httpOnly: true, secure: true, sameSite: 'strict' })"
        );
      }
      return buildResult(lines, lineIdx, before, '쿠키 보안 플래그 추가: httpOnly, secure, sameSite=strict');
    }

    // cookie/session config with false flags
    if (/httpOnly\s*:\s*false/.test(line)) {
      lines[lineIdx] = line.replace(/httpOnly\s*:\s*false/, 'httpOnly: true');
      return buildResult(lines, lineIdx, before, '쿠키 httpOnly: false → true 변경');
    }
    if (/secure\s*:\s*false/.test(line)) {
      lines[lineIdx] = line.replace(/secure\s*:\s*false/, 'secure: true');
      return buildResult(lines, lineIdx, before, '쿠키 secure: false → true 변경');
    }
    return null;
  },

  'SCG-AUF-CORS-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();

    // cors() with no args → cors with env-based origins
    if (/cors\s*\(\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(
        /cors\s*\(\s*\)/,
        "cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'], credentials: true })"
      );
      return buildResult(lines, lineIdx, before, 'CORS 무제한 허용 → 환경변수 기반 출처 제한');
    }
    // origin: '*' → env-based
    if (/origin\s*:\s*['"]\*['"]/.test(line)) {
      lines[lineIdx] = line.replace(
        /origin\s*:\s*['"]\*['"]/,
        "origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']"
      );
      return buildResult(lines, lineIdx, before, "CORS origin: '*' → 환경변수 기반 출처 제한");
    }
    // origin: true → env-based
    if (/origin\s*:\s*true/.test(line)) {
      lines[lineIdx] = line.replace(
        /origin\s*:\s*true/,
        "origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']"
      );
      return buildResult(lines, lineIdx, before, 'CORS origin: true → 환경변수 기반 출처 제한');
    }
    // Access-Control-Allow-Origin: *
    if (/['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/.test(line)) {
      lines[lineIdx] = line.replace(/['"]\*['"]/, "req.headers.origin || 'http://localhost:3000'");
      return buildResult(lines, lineIdx, before, 'Access-Control-Allow-Origin: * → 동적 출처 검증');
    }
    return null;
  },

  'SCG-AUF-HASH-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();

    // password context → bcrypt
    if (/(?:password|passwd|pwd)/i.test(line)) {
      if (/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        const varMatch = line.match(/(?:const|let|var)\s+(\w+)/);
        const passwordVar = line.match(/\.update\s*\((.+?)\)/)?.[1] ?? 'password';
        lines[lineIdx] = `${indent}const ${varMatch?.[1] ?? 'hash'} = await bcrypt.hash(${passwordVar}, 12);`;
        return { ...buildResult(lines, lineIdx, before, '취약한 해시(MD5/SHA1) → bcrypt 변환 (비밀번호 해싱)'), imports: ["import bcrypt from 'bcrypt';"] };
      }
    }
    // general hash → sha256
    if (/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/, "createHash('sha256')");
      return buildResult(lines, lineIdx, before, '취약한 해시(MD5/SHA1) → SHA-256 변환');
    }
    return null;
  },

  'SCG-AUF-SESSION-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // Short secret → env var
    if (/secret\s*:\s*['"][^'"]{1,10}['"]/.test(line)) {
      lines[lineIdx] = line.replace(/secret\s*:\s*['"][^'"]{1,10}['"]/, "secret: process.env.SESSION_SECRET");
      return buildResult(lines, lineIdx, before, '짧은 세션 시크릿 → process.env.SESSION_SECRET 환경변수 전환');
    }
    // resave: true → false
    if (/resave\s*:\s*true/.test(line)) {
      lines[lineIdx] = line.replace(/resave\s*:\s*true/, 'resave: false');
      return buildResult(lines, lineIdx, before, '세션 resave: true → false 변경 (불필요한 세션 저장 방지)');
    }
    return null;
  },

  // ═══════════════════════════════════════════════════
  // SERVER
  // ═══════════════════════════════════════════════════

  'SCG-SRV-ERR-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    if (!/res\.(?:json|send)\s*\(\s*(?:err|error|e)\s*\)/.test(line) &&
        !/res\.(?:json|send)\s*\(\s*\{[^}]*stack\s*:/.test(line) &&
        !/res\.status\s*\(\s*500\s*\)\.(?:json|send)\s*\(\s*(?:err|error)\s*\)/.test(line)) return null;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';
    lines[lineIdx] = `${indent}console.error(err); res.status(500).json({ error: '서버 오류가 발생했습니다.' });`;
    return buildResult(lines, lineIdx, before, '에러 객체 노출 방지 → 서버 측 로깅 + 일반 에러 응답');
  },

  'SCG-SRV-DOS-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    if (/express\.json\s*\(\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(/express\.json\s*\(\s*\)/, "express.json({ limit: '1mb' })");
      return buildResult(lines, lineIdx, before, 'body parser에 크기 제한(1MB) 추가 (DoS 방지)');
    }
    if (/bodyParser\.json\s*\(\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(/bodyParser\.json\s*\(\s*\)/, "bodyParser.json({ limit: '1mb' })");
      return buildResult(lines, lineIdx, before, 'body parser에 크기 제한(1MB) 추가 (DoS 방지)');
    }
    return null;
  },

  'SCG-SRV-JWT-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // jwt.decode(token) → jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })
    if (/jwt\.decode\s*\(/.test(line) && !/jwt\.verify/.test(line)) {
      lines[lineIdx] = line.replace(
        /jwt\.decode\s*\(\s*([^)]+)\)/,
        "jwt.verify($1, process.env.JWT_SECRET, { algorithms: ['HS256'] })"
      );
      return buildResult(lines, lineIdx, before, 'jwt.decode() → jwt.verify() 변환 (서명 검증 필수)');
    }
    // jwt.verify without algorithms → add algorithms
    if (/jwt\.verify\s*\([^)]*\)/.test(line) && !/algorithms/.test(line)) {
      lines[lineIdx] = line.replace(
        /(jwt\.verify\s*\([^,]+,\s*[^,)]+)\s*\)/,
        "$1, { algorithms: ['HS256'] })"
      );
      return buildResult(lines, lineIdx, before, 'jwt.verify()에 algorithms 옵션 추가 (알고리즘 혼동 방지)');
    }
    // algorithm: 'none'
    if (/algorithm\s*:\s*['"]none['"]/i.test(line)) {
      lines[lineIdx] = line.replace(/algorithm\s*:\s*['"]none['"]/i, "algorithms: ['HS256']");
      return buildResult(lines, lineIdx, before, "JWT algorithm 'none' → 'HS256' 변경 (보안 강화)");
    }
    return null;
  },

  'SCG-SRV-PROTO-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    if (/Object\.assign\s*\(\s*\{\}/.test(line)) {
      const srcMatch = line.match(/Object\.assign\s*\(\s*\{\}\s*,\s*(.+?)\s*\)/);
      if (srcMatch) {
        lines[lineIdx] = `${indent}const __sanitized = Object.fromEntries(Object.entries(${srcMatch[1]}).filter(([k]) => !['__proto__', 'constructor', 'prototype'].includes(k)));`;
        return buildResult(lines, lineIdx, before, '프로토타입 오염 방지: __proto__/constructor/prototype 키 필터링');
      }
    }
    return null;
  },

  'SCG-SRV-CMD-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    if (/shell\s*:\s*true/.test(line)) {
      lines[lineIdx] = line.replace(/shell\s*:\s*true/, 'shell: false');
      return buildResult(lines, lineIdx, before, 'shell: true → false 변경 (명령어 인젝션 방지)');
    }
    return null;
  },

  // ═══════════════════════════════════════════════════
  // CRYPTO
  // ═══════════════════════════════════════════════════

  'SCG-CRY-RAND-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // Math.random().toString(36) → crypto.randomBytes(32).toString('hex')
    if (/Math\.random\s*\(\s*\)\.toString\s*\(\s*36\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(
        /Math\.random\s*\(\s*\)\.toString\s*\(\s*36\s*\)(?:\.(?:substring|slice|substr)\s*\([^)]*\))?/,
        "crypto.randomBytes(32).toString('hex')"
      );
      return { ...buildResult(lines, lineIdx, before, 'Math.random().toString(36) → crypto.randomBytes() 변환 (안전한 난수)'), imports: ["import crypto from 'crypto';"] };
    }
    // General Math.random() in security context
    if (/Math\.random\s*\(\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(/Math\.random\s*\(\s*\)/, "parseInt(crypto.randomBytes(4).toString('hex'), 16) / 0xFFFFFFFF");
      return { ...buildResult(lines, lineIdx, before, 'Math.random() → crypto.randomBytes() 변환 (암호학적 난수)'), imports: ["import crypto from 'crypto';"] };
    }
    return null;
  },

  'SCG-CRY-ALGO-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // createCipher('des'...) → createCipheriv('aes-256-gcm'...)
    if (/createCipher(?:iv)?\s*\(\s*['"](?:des|rc4|blowfish|des-ede|rc2)['"]/i.test(line)) {
      lines[lineIdx] = line.replace(/['"](?:des|rc4|blowfish|des-ede|rc2)['"]/i, "'aes-256-gcm'");
      return buildResult(lines, lineIdx, before, '취약한 암호화 알고리즘 → AES-256-GCM 변환');
    }
    if (/AES.*?ECB/i.test(line)) {
      lines[lineIdx] = line.replace(/ECB/gi, 'GCM');
      return buildResult(lines, lineIdx, before, 'AES-ECB → AES-GCM 변환 (안전한 암호화 모드)');
    }
    return null;
  },

  'SCG-CRY-KEY-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const keyMatch = line.match(/((?:encryption[_.]?key|crypto[_.]?key|secret[_.]?key|aes[_.]?key)\s*[:=]\s*)['"][^'"]+['"]/i);
    if (keyMatch) {
      const envKey = keyMatch[1].replace(/\s*[:=]\s*$/, '').trim().replace(/([a-z])([A-Z])/g, '$1_$2').replace(/[.\s-]/g, '_').toUpperCase();
      lines[lineIdx] = line.replace(/['"][^'"]{8,}['"]/, `process.env.${envKey}`);
      return buildResult(lines, lineIdx, before, `하드코딩된 암호화 키 → process.env.${envKey} 환경변수 전환`);
    }
    // Inline key in createCipher
    if (/createCipher(?:iv)?\s*\([^,]+,\s*['"][^'"]{8,}['"]/.test(line)) {
      lines[lineIdx] = line.replace(
        /(createCipher(?:iv)?\s*\([^,]+,\s*)['"][^'"]+['"]/,
        "$1Buffer.from(process.env.ENCRYPTION_KEY, 'hex')"
      );
      return buildResult(lines, lineIdx, before, '하드코딩된 암호화 키 → 환경변수 전환');
    }
    return null;
  },

  'SCG-CRY-HASH-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    if (/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/, "createHash('sha256')");
      return buildResult(lines, lineIdx, before, '취약한 해시(MD5/SHA1) → SHA-256 변환 (무결성 검증)');
    }
    if (/hashlib\.(?:md5|sha1)\s*\(/.test(line)) {
      lines[lineIdx] = line.replace(/hashlib\.(?:md5|sha1)/, 'hashlib.sha256');
      return buildResult(lines, lineIdx, before, '취약한 해시(MD5/SHA1) → SHA-256 변환');
    }
    return null;
  },

  'SCG-CRY-TLS-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    if (/NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0/.test(line)) {
      lines[lineIdx] = line.replace(/NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0['"]?/, "/* [보안] TLS 검증 비활성화 제거됨 */ NODE_TLS_REJECT_UNAUTHORIZED = '1'");
      return buildResult(lines, lineIdx, before, 'TLS 인증서 검증 활성화 (MITM 방지)');
    }
    if (/rejectUnauthorized\s*:\s*false/.test(line)) {
      lines[lineIdx] = line.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true');
      return buildResult(lines, lineIdx, before, 'rejectUnauthorized: false → true (TLS 검증 활성화)');
    }
    return null;
  },

  // ═══════════════════════════════════════════════════
  // CONFIG
  // ═══════════════════════════════════════════════════

  'SCG-MCF-DEBUG-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // debug: true → debug: process.env.NODE_ENV !== 'production'
    if (/(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|['"]true['"])/.test(line)) {
      lines[lineIdx] = line.replace(
        /(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|['"]true['"])/i,
        "debug: process.env.NODE_ENV !== 'production'"
      );
      return buildResult(lines, lineIdx, before, "디버그 모드 → 환경변수 기반 조건부 활성화");
    }
    // app.debug = True (Python)
    if (/app\.(?:debug|DEBUG)\s*=\s*True/.test(line)) {
      lines[lineIdx] = line.replace(/app\.(?:debug|DEBUG)\s*=\s*True/i, "app.debug = os.environ.get('FLASK_ENV') != 'production'");
      return buildResult(lines, lineIdx, before, '디버그 모드 → 환경변수 기반 조건부 활성화');
    }
    return null;
  },

  'SCG-MCF-ERR-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    // res.json({error: err.stack}) or res.send(err.message)
    if (/(?:err|error)\.(?:stack|message)/.test(line) && /res\.(?:json|send|status)/.test(line)) {
      lines[lineIdx] = `${indent}console.error(err); res.status(500).json({ error: '서버 오류가 발생했습니다.' });`;
      return buildResult(lines, lineIdx, before, '에러 상세 노출 방지 → 일반 에러 응답 + 서버 로깅');
    }
    // .catch(err => res.json(err))
    if (/\.catch\s*\(.*?res\..*?(?:err|error)\s*\)/.test(line)) {
      lines[lineIdx] = line.replace(
        /res\.(?:json|send)\s*\(\s*(?:err|error|e)\s*\)/,
        "res.status(500).json({ error: '서버 오류가 발생했습니다.' })"
      );
      return buildResult(lines, lineIdx, before, 'catch 에러 노출 방지 → 일반 에러 응답');
    }
    return null;
  },

  'SCG-MCF-HELMET-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    if (!/express\s*\(\s*\)/.test(line)) return null;

    // Find the line after express() and insert helmet
    const indent = line.match(/^(\s*)/)?.[1] ?? '';
    const varMatch = code.match(/(?:const|let|var)\s+(\w+)\s*=\s*express\s*\(\s*\)/);
    const appVar = varMatch?.[1] ?? 'app';

    lines.splice(lineIdx + 1, 0, `${indent}${appVar}.use(helmet());`);
    return { ...buildResult(lines, lineIdx, before, 'helmet() 미들웨어 자동 주입 (보안 헤더 설정)'), imports: ["import helmet from 'helmet';"] };
  },

  'SCG-MCF-RATE-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    const indent = line.match(/^(\s*)/)?.[1] ?? '';

    // app.post('/login', handler) → app.post('/login', loginLimiter, handler)
    const routeMatch = line.match(/(app\.(?:post|put)\s*\(\s*['"][^'"]+['"]\s*,\s*)/);
    if (routeMatch) {
      lines[lineIdx] = line.replace(routeMatch[1], `${routeMatch[1]}loginLimiter, `);
      lines.splice(lineIdx, 0,
        `${indent}const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: '요청 횟수를 초과했습니다. 잠시 후 다시 시도하세요.' } });`
      );
      return { ...buildResult(lines, lineIdx, before, 'Rate Limiting 미들웨어 자동 주입 (무차별 대입 방지)'), imports: ["import rateLimit from 'express-rate-limit';"] };
    }
    return null;
  },

  'SCG-MCF-HTTP-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    if (/['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line)) {
      lines[lineIdx] = line.replace(/['"]http:\/\//g, (m) => m.replace('http://', 'https://'));
      return buildResult(lines, lineIdx, before, 'HTTP → HTTPS 변환 (전송 보안 강화)');
    }
    return null;
  },

  'SCG-LOG-SENS-001': (code, vuln) => {
    const ctx = getLine(code, vuln);
    if (!ctx) return null;
    const { lines, lineIdx, line } = ctx;

    const before = line.trim();
    // Replace sensitive field references with masked versions
    const sensitiveFields = /\b(password|passwd|pwd|token|secret|credit.?card|ssn|social.?security)\b/gi;
    if (sensitiveFields.test(line) && /console\.log|logger\./i.test(line)) {
      lines[lineIdx] = line.replace(
        /(console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug))\s*\((.+)\)/,
        (match, fn, args) => {
          const masked = args.replace(sensitiveFields, "'[REDACTED]'");
          return `${fn}(${masked})`;
        }
      );
      return buildResult(lines, lineIdx, before, '로그 민감정보 마스킹: 비밀번호/토큰 등 [REDACTED] 처리');
    }
    return null;
  },
};

// target="_blank" → rel="noopener noreferrer" 추가 (범용)
function fixTargetBlank(code: string): { code: string; fixes: AppliedFix[] } {
  const fixes: AppliedFix[] = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/target\s*=\s*["']_blank["']/i.test(line) && !/rel\s*=\s*["'][^"']*noopener/i.test(line)) {
      const before = line.trim();
      lines[i] = line.replace(
        /(target\s*=\s*["']_blank["'])/i,
        '$1 rel="noopener noreferrer"'
      );
      fixes.push({
        line: i + 1,
        ruleId: 'SCG-MISC-TARGET-BLANK',
        severity: 'low',
        description: 'target="_blank"에 rel="noopener noreferrer" 추가',
        before,
        after: lines[i].trim(),
      });
    }
  }

  return { code: lines.join('\n'), fixes };
}

// password 필드 autocomplete 추가
function fixPasswordFields(code: string): { code: string; fixes: AppliedFix[] } {
  const fixes: AppliedFix[] = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/type\s*=\s*["']password["']/i.test(line) && !/autocomplete/i.test(line)) {
      const before = line.trim();
      lines[i] = line.replace(
        /(type\s*=\s*["']password["'])/i,
        '$1 autocomplete="current-password"'
      );
      fixes.push({
        line: i + 1,
        ruleId: 'SCG-MISC-PASSWORD-AUTOCOMPLETE',
        severity: 'info',
        description: 'password 필드에 autocomplete 속성 추가',
        before,
        after: lines[i].trim(),
      });
    }
  }

  return { code: lines.join('\n'), fixes };
}

// form에 CSRF 토큰 필드 + 서버 fetch 스크립트 추가
function fixCSRFTokens(code: string): { code: string; fixes: AppliedFix[] } {
  const fixes: AppliedFix[] = [];

  if (/<form\b/i.test(code) && !/csrf/i.test(code)) {
    const csrfField = `    <input type="hidden" name="_csrf" value="" id="csrfToken"><!-- [보안] CSRF 토큰 (서버에서 동적 발급) -->`;
    code = code.replace(
      /(<form[^>]*>)/gi,
      (match) => `${match}\n${csrfField}`
    );
    fixes.push({
      line: 0,
      ruleId: 'SCG-MISC-CSRF',
      severity: 'medium',
      description: 'form에 CSRF 토큰 hidden 필드 추가',
      before: '<form ...>',
      after: '<form ...> + CSRF 토큰 필드',
    });
  }

  if (/<form\b/i.test(code) && /csrf/i.test(code) && !/__fetchCsrfToken/.test(code)) {
    const csrfScript = [
      '',
      '  <script>',
      '  // [보안] CSRF 토큰을 서버에서 동적으로 획득',
      '  async function __fetchCsrfToken() {',
      "    try { const r = await fetch('/api/csrf-token', { credentials: 'same-origin' });",
      "      const d = await r.json(); document.getElementById('csrfToken').value = d.token;",
      '    } catch(e) { console.warn(\'CSRF token fetch failed\'); }',
      '  }',
      "  window.addEventListener('DOMContentLoaded', __fetchCsrfToken);",
      '  </script>',
    ].join('\n');

    if (/<\/body>/i.test(code)) {
      code = code.replace(/(<\/body>)/i, `${csrfScript}\n$1`);
      fixes.push({
        line: 0,
        ruleId: 'SCG-MISC-CSRF-FETCH',
        severity: 'medium',
        description: 'CSRF 토큰 서버 동적 획득 스크립트 추가',
        before: '</body>',
        after: '</body> + CSRF fetch 스크립트',
      });
    }
  }

  return { code, fixes };
}

function tryAutoFix(code: string, vuln: Vulnerability): AutoFixResult | null {
  const handler = FIX_HANDLERS[vuln.ruleId];
  if (handler) {
    return handler(code, vuln);
  }

  // CWE 기반 범용 수정
  switch (vuln.cweId) {
    case 'CWE-79':
      return tryFixXSS(code, vuln);
    case 'CWE-89':
      return FIX_HANDLERS['SCG-INJ-SQL-001']?.(code, vuln) ?? null;
    case 'CWE-94':
      return FIX_HANDLERS['SCG-INJ-CODE-001']?.(code, vuln) ?? null;
    case 'CWE-78':
      return FIX_HANDLERS['SCG-INJ-CMD-001']?.(code, vuln) ?? null;
    case 'CWE-798':
      return FIX_HANDLERS['SCG-AUF-SECRET-001']?.(code, vuln) ?? null;
    case 'CWE-328':
      return FIX_HANDLERS['SCG-CRY-HASH-001']?.(code, vuln) ?? null;
    case 'CWE-330':
      return FIX_HANDLERS['SCG-CRY-RAND-001']?.(code, vuln) ?? null;
    case 'CWE-327':
      return FIX_HANDLERS['SCG-CRY-ALGO-001']?.(code, vuln) ?? null;
    case 'CWE-209':
      return FIX_HANDLERS['SCG-SRV-ERR-001']?.(code, vuln) ?? null;
    case 'CWE-614':
      return FIX_HANDLERS['SCG-AUF-COOKIE-001']?.(code, vuln) ?? null;
    case 'CWE-295':
      return FIX_HANDLERS['SCG-CRY-TLS-001']?.(code, vuln) ?? null;
    default:
      return null;
  }
}

function tryFixXSS(code: string, vuln: Vulnerability): AutoFixResult | null {
  const lines = code.split('\n');
  const lineIdx = vuln.location.startLine - 1;
  if (lineIdx < 0 || lineIdx >= lines.length) return null;
  const line = lines[lineIdx];

  if (/\.innerHTML\s*=/.test(line)) {
    if (isSafeInnerHtmlUsage(line)) return null;
    const before = line.trim();
    lines[lineIdx] = line.replace(/\.innerHTML\s*=/, '.textContent =');
    return {
      code: lines.join('\n'),
      description: 'innerHTML → textContent 변경 (XSS 방지)',
      before,
      after: lines[lineIdx].trim(),
    };
  }

  return null;
}


// ─── innerHTML 안전 패턴 판별 ───

const SAFE_INNER_HTML_PATTERNS = [
  /\.innerHTML\s*=\s*['"]\s*['"]/,
  /\.innerHTML\s*=\s*['"]<(?:svg|i|span|img|br|hr|b|em|strong|icon)\b/i,
  /\.innerHTML\s*=\s*(?:DOMPurify\.sanitize|sanitize|sanitizeHtml|xss)\s*\(/i,
  /\.innerHTML\s*=\s*['"]&#/,
];

function isSafeInnerHtmlUsage(line: string): boolean {
  return SAFE_INNER_HTML_PATTERNS.some((p) => p.test(line));
}

// ─── HTML 종합 강화 ───

function hardenHTML(code: string, appliedFixes: AppliedFix[]): string {
  const blankResult = fixTargetBlank(code);
  code = blankResult.code;
  appliedFixes.push(...blankResult.fixes);

  const passwordResult = fixPasswordFields(code);
  code = passwordResult.code;
  appliedFixes.push(...passwordResult.fixes);

  const csrfResult = fixCSRFTokens(code);
  code = csrfResult.code;
  appliedFixes.push(...csrfResult.fixes);

  return code;
}

// ─── 서버 사이드 필수 구현 가이드 ───

function buildServerHeaderGuide(headers: string[]): string {
  const lines: string[] = [];
  lines.push('## [필수] 서버 응답 헤더 설정');
  lines.push('meta 태그는 폴백입니다. 반드시 서버 응답 헤더로도 설정하세요.');
  lines.push('');
  lines.push('```typescript');
  lines.push('// Express 미들웨어로 보안 헤더 설정');
  lines.push('app.use((req, res, next) => {');
  for (const h of headers) {
    if (/Content-Security-Policy/i.test(h)) {
      lines.push("  res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\");");
    } else if (/X-Frame/i.test(h)) {
      lines.push("  res.setHeader('X-Frame-Options', 'DENY');");
    } else if (/X-Content-Type/i.test(h)) {
      lines.push("  res.setHeader('X-Content-Type-Options', 'nosniff');");
    } else if (/Referrer/i.test(h)) {
      lines.push("  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');");
    }
  }
  lines.push("  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');");
  lines.push('  next();');
  lines.push('});');
  lines.push('```');
  return lines.join('\n');
}

function buildRateLimitServerGuide(): string {
  const lines: string[] = [];
  lines.push('## [필수] 서버 Rate Limiting');
  lines.push('클라이언트측 rate limiting은 DevTools로 우회 가능합니다. 서버에서 반드시 구현하세요.');
  lines.push('');
  lines.push('```typescript');
  lines.push("import rateLimit from 'express-rate-limit';");
  lines.push('');
  lines.push('const loginLimiter = rateLimit({');
  lines.push('  windowMs: 15 * 60 * 1000, // 15분');
  lines.push('  max: 5, // 최대 5회');
  lines.push("  message: { error: '로그인 시도 횟수를 초과했습니다. 15분 후 다시 시도하세요.' },");
  lines.push('  standardHeaders: true,');
  lines.push('  legacyHeaders: false,');
  lines.push('});');
  lines.push('');
  lines.push("app.post('/api/login', loginLimiter, loginHandler);");
  lines.push("app.post('/api/register', loginLimiter, registerHandler);");
  lines.push('```');
  return lines.join('\n');
}

function buildCsrfServerGuide(): string {
  const lines: string[] = [];
  lines.push('## [필수] 서버 CSRF 토큰 발급/검증');
  lines.push('클라이언트의 CSRF 토큰은 서버에서 발급하고 검증해야 합니다.');
  lines.push('');
  lines.push('```typescript');
  lines.push("import crypto from 'crypto';");
  lines.push('');
  lines.push("// CSRF 토큰 발급 엔드포인트");
  lines.push("app.get('/api/csrf-token', (req, res) => {");
  lines.push("  const token = crypto.randomBytes(32).toString('hex');");
  lines.push('  req.session.csrfToken = token;');
  lines.push('  res.json({ token });');
  lines.push('});');
  lines.push('');
  lines.push("// CSRF 토큰 검증 미들웨어");
  lines.push("function verifyCsrf(req, res, next) {");
  lines.push("  const token = req.headers['x-csrf-token'] || req.body._csrf;");
  lines.push("  if (!token || token !== req.session.csrfToken) {");
  lines.push("    return res.status(403).json({ error: 'CSRF 토큰이 유효하지 않습니다' });");
  lines.push('  }');
  lines.push('  next();');
  lines.push('}');
  lines.push("app.post('/api/login', verifyCsrf, loginHandler);");
  lines.push('```');
  return lines.join('\n');
}
