import { z } from 'zod';
import { scanCode } from '../engine/scanner.js';
import { applySecureFixes } from '../engine/secure-fixer.js';
import {
  getPatternsByPackage,
  scanCodeForCvePatterns,
  getAllCvePatterns,
  type CveCodePattern,
} from '../services/cve-code-patterns.js';
import { getKnowledgeByCwe } from '../knowledge/portswigger-remediation.js';

export const secureCodeSchema = z.object({
  code: z.string().describe('시큐어코딩을 적용할 소스 코드'),
  language: z
    .enum(['javascript', 'typescript', 'python', 'java'])
    .optional()
    .describe('프로그래밍 언어 (자동 감지)'),
  context: z
    .enum(['frontend', 'backend', 'fullstack', 'api', 'config'])
    .optional()
    .describe('코드 컨텍스트'),
  show_comparison: z
    .boolean()
    .optional()
    .default(false)
    .describe('true이면 원본 코드와 시큐어코딩 적용 코드를 나란히 비교하여 보여줍니다'),
});

export type SecureCodeInput = z.infer<typeof secureCodeSchema>;

function detectLibraries(code: string): string[] {
  const libs = new Set<string>();
  const importRegex = /(?:import\s+.*?\s+from\s+['"]([^'"./][^'"]*?)['"]|require\s*\(\s*['"]([^'"./][^'"]*?)['"]\s*\))/g;
  let match: RegExpExecArray | null;
  while ((match = importRegex.exec(code)) !== null) {
    const pkg = match[1] || match[2];
    if (pkg) {
      const base = pkg.startsWith('@') ? pkg.split('/').slice(0, 2).join('/') : pkg.split('/')[0];
      libs.add(base);
    }
  }
  return [...libs];
}

export async function handleSecureCode(input: SecureCodeInput) {
  const scanResult = scanCode(input.code, {
    language: input.language,
    context: input.context,
    severityThreshold: 'info',
  });

  const fixResult = applySecureFixes(input.code, scanResult.vulnerabilities);

  const postScan = scanCode(fixResult.fixedCode, {
    language: input.language,
    context: input.context,
    severityThreshold: 'info',
  });
  const resolved = scanResult.summary.totalIssues - postScan.summary.totalIssues;
  const remaining = postScan.summary.totalIssues;

  const detectedLibs = detectLibraries(input.code);
  const cveFindings = runCveCheck(input.code, detectedLibs);

  const total = scanResult.summary.totalIssues;
  const fixed = fixResult.appliedFixes.length;
  const manual = fixResult.manualFixes.length;
  const headers = fixResult.injectedHeaders.length;
  const imports = fixResult.addedImports?.length ?? 0;
  const cveCount = cveFindings.length;

  if (total === 0 && headers === 0 && cveCount === 0) {
    return { content: [{ type: 'text' as const, text: '✅ 취약점 없음. 코드가 안전합니다.' }] };
  }

  const patches: string[] = [];
  patches.push(`취약점 ${total}개 발견, 자동수정 ${fixed}개, 수동확인 ${manual}개, 보안헤더 ${headers}개, import ${imports}개 추가`);
  if (cveCount > 0) {
    patches.push(`🔍 CVE 패턴 ${cveCount}개 감지 (${detectedLibs.join(', ')} 라이브러리 자동 검사)`);
  }
  if (resolved > 0) {
    patches.push(`🔒 재스캔 검증: ${resolved}개 해결됨, ${remaining}개 수동 확인 필요`);
  }
  patches.push('');

  // 전/후 비교 모드
  if (input.show_comparison) {
    patches.push(buildComparison(input.code, fixResult.fixedCode, fixResult, scanResult.summary));
  } else {
    patches.push('아래 수정사항을 코드에 적용하세요:');
    patches.push('');

    if (fixResult.injectedHeaders.length > 0) {
      patches.push('## <head> 안에 추가:');
      patches.push('```html');
      patches.push('<!-- [보안] 보안 헤더 -->');
      for (const h of fixResult.injectedHeaders) {
        const tag = getHeaderTag(h);
        if (tag) patches.push(tag);
      }
      patches.push('```');
      patches.push('');
    }

    if (fixResult.appliedFixes.length > 0) {
      patches.push('## 코드 수정:');
      for (const fix of fixResult.appliedFixes) {
        if (fix.before && fix.after && fix.before !== fix.after) {
          patches.push(`- 라인${fix.line}: \`${trunc(fix.before)}\` → \`${trunc(fix.after)}\``);
        } else {
          patches.push(`- ${fix.description}`);
        }
      }
      patches.push('');
    }

    if (fixResult.appliedFixes.some((f) => f.ruleId === 'SCG-MISC-CSRF')) {
      patches.push('## <form> 바로 안에 추가:');
      patches.push('```html');
      patches.push('<input type="hidden" name="_csrf" value="" id="csrfToken">');
      patches.push('```');
      patches.push('');
    }
  }

  if (fixResult.addedImports && fixResult.addedImports.length > 0) {
    patches.push('## 자동 추가된 Import:');
    for (const imp of fixResult.addedImports) {
      patches.push(`- \`${imp}\``);
    }
    patches.push('');
  }

  if (fixResult.manualFixes.length > 0) {
    patches.push('## 수동 확인 필요:');
    for (const fix of fixResult.manualFixes) {
      patches.push(`- 라인${fix.line} ${fix.description}: ${fix.suggestion}`);
    }
    patches.push('');
  }

  if (fixResult.serverGuides.length > 0) {
    patches.push('---');
    patches.push('');
    patches.push('# 서버 사이드 필수 구현 가이드');
    patches.push('');
    for (const guide of fixResult.serverGuides) {
      patches.push(guide);
      patches.push('');
    }
  }

  if (cveFindings.length > 0) {
    patches.push('---');
    patches.push('');
    patches.push('# CVE 취약점 패턴 자동 검사 결과');
    patches.push('');
    if (detectedLibs.length > 0) {
      patches.push(`감지된 라이브러리: ${detectedLibs.map((l) => '`' + l + '`').join(', ')}`);
      patches.push('');
    }
    for (const finding of cveFindings) {
      patches.push(`## ⚠️ ${finding.cveId} (${finding.pattern.packageName})`);
      patches.push('');
      patches.push(`- **위험:** ${finding.pattern.descriptionKo}`);
      patches.push(`- **라인 ${finding.line}:** \`${finding.matchedCode}\``);
      patches.push(`- **수정 방안:** ${finding.pattern.codeRemediationKo}`);
      patches.push('');
      patches.push('**안전한 코드 예시:**');
      patches.push('```');
      patches.push(finding.pattern.safeAlternative);
      patches.push('```');

      const ps = getKnowledgeByCwe(finding.pattern.cweId);
      if (ps) {
        patches.push('');
        patches.push(`**방어 기법 (PortSwigger):** ${ps.preventionTechniquesKo[0]}`);
        patches.push(`📚 ${ps.portswiggerUrl}`);
      }
      patches.push('');
    }
  } else if (detectedLibs.length > 0) {
    patches.push('');
    patches.push(`✅ CVE 패턴 검사: ${detectedLibs.map((l) => '`' + l + '`').join(', ')} — 알려진 취약 패턴 없음`);
  }

  return { content: [{ type: 'text' as const, text: patches.join('\n') }] };
}

interface CveFinding {
  cveId: string;
  line: number;
  matchedCode: string;
  pattern: CveCodePattern;
}

function runCveCheck(code: string, detectedLibs: string[]): CveFinding[] {
  const patternsToCheck: CveCodePattern[] = [];

  for (const lib of detectedLibs) {
    patternsToCheck.push(...getPatternsByPackage(lib));
  }

  const allPatterns = getAllCvePatterns();
  for (const p of allPatterns) {
    if (!patternsToCheck.includes(p)) {
      const pkgRe = new RegExp(`\\b${p.packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
      if (pkgRe.test(code)) {
        patternsToCheck.push(p);
      }
    }
  }

  if (patternsToCheck.length === 0) return [];
  return scanCodeForCvePatterns(code, patternsToCheck);
}

function trunc(s: string, n = 60): string {
  return s.length > n ? s.slice(0, n) + '...' : s;
}

function getHeaderTag(name: string): string | null {
  if (name.includes('Content-Security-Policy')) {
    return '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\';">';
  }
  if (name.includes('X-Frame')) {
    return '<meta http-equiv="X-Frame-Options" content="DENY">';
  }
  if (name.includes('X-Content-Type')) {
    return '<meta http-equiv="X-Content-Type-Options" content="nosniff">';
  }
  if (name.includes('Referrer')) {
    return '<meta name="referrer" content="strict-origin-when-cross-origin">';
  }
  return null;
}

// ─── 전/후 비교 (Comparison) ───

import type { FixResult } from '../engine/secure-fixer.js';
import type { ScanSummary } from '../types/index.js';

interface DiffLine {
  type: 'unchanged' | 'removed' | 'added' | 'modified';
  lineNum: number;
  original: string;
  secured: string;
  ruleId?: string;
  description?: string;
}

/**
 * 원본과 수정본을 라인 단위로 비교해 unified diff 형태의 텍스트를 생성한다.
 */
export function generateDiff(original: string, secured: string): DiffLine[] {
  const origLines = original.split('\n');
  const secLines = secured.split('\n');
  const maxLen = Math.max(origLines.length, secLines.length);
  const diff: DiffLine[] = [];

  let oi = 0;
  let si = 0;

  while (oi < origLines.length || si < secLines.length) {
    const origLine = oi < origLines.length ? origLines[oi] : undefined;
    const secLine = si < secLines.length ? secLines[si] : undefined;

    if (origLine !== undefined && secLine !== undefined) {
      if (origLine === secLine) {
        diff.push({ type: 'unchanged', lineNum: oi + 1, original: origLine, secured: secLine });
        oi++;
        si++;
      } else {
        const insertedByFix = isInsertedLine(secLine);
        if (insertedByFix && oi < origLines.length && origLines[oi] === secLines[si + 1]) {
          diff.push({ type: 'added', lineNum: si + 1, original: '', secured: secLine });
          si++;
        } else {
          diff.push({ type: 'modified', lineNum: oi + 1, original: origLine, secured: secLine });
          oi++;
          si++;
          while (si < secLines.length && oi <= origLines.length && secLines[si] !== origLines[oi]) {
            if (isInsertedLine(secLines[si])) {
              diff.push({ type: 'added', lineNum: si + 1, original: '', secured: secLines[si] });
              si++;
            } else {
              break;
            }
          }
        }
      }
    } else if (origLine !== undefined) {
      diff.push({ type: 'removed', lineNum: oi + 1, original: origLine, secured: '' });
      oi++;
    } else if (secLine !== undefined) {
      diff.push({ type: 'added', lineNum: si + 1, original: '', secured: secLine });
      si++;
    }
  }

  return diff;
}

function isInsertedLine(line: string): boolean {
  return /<!--\s*\[보안\]/.test(line)
    || /\/\*\s*\[보안/.test(line)
    || /<meta\s+http-equiv=/i.test(line)
    || /<input\s+type="hidden"\s+name="_csrf"/i.test(line)
    || /csrfToken/i.test(line);
}

function buildComparison(
  original: string,
  secured: string,
  fixResult: FixResult,
  summary: ScanSummary,
): string {
  const out: string[] = [];
  const diff = generateDiff(original, secured);

  const changedLines = diff.filter((d) => d.type !== 'unchanged');
  const severityBadge: Record<string, string> = {
    critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️',
  };

  // 심각도 요약
  out.push('## 보안 분석 요약');
  out.push('');
  out.push('| 심각도 | 건수 |');
  out.push('|--------|------|');
  if (summary.critical > 0) out.push(`| ${severityBadge.critical} Critical | ${summary.critical} |`);
  if (summary.high > 0) out.push(`| ${severityBadge.high} High | ${summary.high} |`);
  if (summary.medium > 0) out.push(`| ${severityBadge.medium} Medium | ${summary.medium} |`);
  if (summary.low > 0) out.push(`| ${severityBadge.low} Low | ${summary.low} |`);
  if (summary.info > 0) out.push(`| ${severityBadge.info} Info | ${summary.info} |`);
  out.push('');

  // 수정 내역 테이블
  if (fixResult.appliedFixes.length > 0) {
    out.push('## 자동 수정 내역');
    out.push('');
    out.push('| # | 라인 | 규칙 | 심각도 | 설명 |');
    out.push('|---|------|------|--------|------|');
    fixResult.appliedFixes.forEach((fix, i) => {
      const badge = severityBadge[fix.severity] ?? '';
      out.push(`| ${i + 1} | ${fix.line} | ${fix.ruleId} | ${badge} ${fix.severity} | ${fix.description} |`);
    });
    out.push('');
  }

  // 전/후 비교 - 변경된 영역만 context와 함께 보여주기
  out.push('## 코드 비교 (Before → After)');
  out.push('');

  const changeGroups = groupChanges(diff, 2);

  for (const group of changeGroups) {
    out.push('---');
    out.push('');
    const firstChanged = group.find((d) => d.type !== 'unchanged');
    const relatedFix = firstChanged
      ? fixResult.appliedFixes.find((f) => f.line === firstChanged.lineNum)
      : undefined;
    if (relatedFix) {
      out.push(`**${relatedFix.description}** (${relatedFix.ruleId}, ${relatedFix.severity})`);
      out.push('');
    }

    // Before
    out.push('**Before (취약):**');
    out.push('```');
    for (const d of group) {
      if (d.type === 'added') continue;
      const prefix = d.type === 'removed' ? '- ' : d.type === 'modified' ? '- ' : '  ';
      out.push(`${String(d.lineNum).padStart(4)} | ${prefix}${d.original}`);
    }
    out.push('```');
    out.push('');

    // After
    out.push('**After (시큐어):**');
    out.push('```');
    for (const d of group) {
      if (d.type === 'removed') continue;
      const prefix = d.type === 'added' ? '+ ' : d.type === 'modified' ? '+ ' : '  ';
      const lineContent = d.type === 'unchanged' ? d.original : d.secured;
      out.push(`${String(d.lineNum).padStart(4)} | ${prefix}${lineContent}`);
    }
    out.push('```');
    out.push('');
  }

  // 보안 헤더
  if (fixResult.injectedHeaders.length > 0) {
    out.push('## 추가된 보안 헤더');
    out.push('');
    for (const h of fixResult.injectedHeaders) {
      out.push(`- ${h} (meta 태그 삽입됨 - 서버 응답 헤더로도 설정 필요)`);
    }
    out.push('');
  }

  // 서버 사이드 가이드
  if (fixResult.serverGuides.length > 0) {
    out.push('---');
    out.push('');
    out.push('# 서버 사이드 필수 구현 가이드');
    out.push('');
    for (const guide of fixResult.serverGuides) {
      out.push(guide);
      out.push('');
    }
  }

  // 전체 수정 코드
  out.push('## 최종 시큐어코딩 적용 코드');
  out.push('');
  out.push('```');
  out.push(secured);
  out.push('```');
  out.push('');

  return out.join('\n');
}

function groupChanges(diff: DiffLine[], contextLines: number): DiffLine[][] {
  const changeIndices: number[] = [];
  for (let i = 0; i < diff.length; i++) {
    if (diff[i].type !== 'unchanged') changeIndices.push(i);
  }

  if (changeIndices.length === 0) return [];

  const groups: DiffLine[][] = [];
  let currentGroup: { start: number; end: number } = {
    start: Math.max(0, changeIndices[0] - contextLines),
    end: Math.min(diff.length - 1, changeIndices[0] + contextLines),
  };

  for (let ci = 1; ci < changeIndices.length; ci++) {
    const nextStart = Math.max(0, changeIndices[ci] - contextLines);
    const nextEnd = Math.min(diff.length - 1, changeIndices[ci] + contextLines);

    if (nextStart <= currentGroup.end + 1) {
      currentGroup.end = nextEnd;
    } else {
      groups.push(diff.slice(currentGroup.start, currentGroup.end + 1));
      currentGroup = { start: nextStart, end: nextEnd };
    }
  }
  groups.push(diff.slice(currentGroup.start, currentGroup.end + 1));

  return groups;
}
