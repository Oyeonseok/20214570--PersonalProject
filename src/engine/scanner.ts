import type {
  SecurityRule,
  Vulnerability,
  ScanResult,
  Language,
  Severity,
  CodeLocation,
} from '../types/index.js';
import { ALL_RULES, getRulesByLanguage, getRulesForFramework } from '../rules/index.js';
import { detectLanguage } from '../utils/language-detector.js';
import { generateScanId, nowISO, buildSummary, meetsThreshold, truncateCode } from '../utils/helpers.js';

export interface ScanOptions {
  language?: Language;
  framework?: string;
  context?: string;
  severityThreshold?: Severity;
  excludeRules?: string[];
  filePath?: string;
}

export function scanCode(code: string, options: ScanOptions = {}): ScanResult {
  const language = options.language ?? detectLanguage(code, options.filePath);
  const threshold = options.severityThreshold ?? 'low';
  const excludeSet = new Set(options.excludeRules ?? []);

  let applicableRules = getRulesByLanguage(language);

  if (options.framework) {
    applicableRules = applicableRules.filter(
      (r) => !r.frameworks || r.frameworks.length === 0 || r.frameworks.includes(options.framework!)
    );
  }

  applicableRules = applicableRules.filter((r) => !excludeSet.has(r.id));

  const lines = code.split('\n');
  const vulnerabilities: Vulnerability[] = [];
  let vulnCounter = 0;

  for (const rule of applicableRules) {
    if (!meetsThreshold(rule.severity, threshold)) continue;

    const findings = matchRule(rule, code, lines, options.filePath);
    for (const finding of findings) {
      vulnCounter++;
      vulnerabilities.push({
        id: `VULN-${String(vulnCounter).padStart(3, '0')}`,
        ruleId: rule.id,
        title: rule.title,
        titleKo: rule.titleKo,
        severity: rule.severity,
        confidence: rule.confidence,
        category: rule.category,
        cweId: rule.cweId,
        owaspCategory: rule.owaspCategory,
        location: finding.location,
        matchedCode: finding.matchedCode,
        description: rule.description,
        descriptionKo: rule.descriptionKo,
        attackScenario: generateAttackScenario(rule),
        impact: generateImpact(rule),
        remediation: rule.remediation,
      });
    }
  }

  vulnerabilities.sort((a, b) => {
    const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  return {
    scanId: generateScanId(),
    timestamp: nowISO(),
    targetType: options.filePath ? 'file' : 'code',
    language,
    framework: options.framework,
    summary: buildSummary(vulnerabilities),
    vulnerabilities,
    suggestions: generateSuggestions(vulnerabilities, language, options.framework),
  };
}

interface RuleFinding {
  location: CodeLocation;
  matchedCode: string;
}

function matchRule(rule: SecurityRule, fullCode: string, lines: string[], filePath?: string): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const matchedLines = new Set<number>();

  for (const pattern of rule.patterns) {
    if (pattern.multiline) {
      const matches = fullCode.matchAll(new RegExp(pattern.regex.source, pattern.regex.flags + (pattern.regex.flags.includes('g') ? '' : 'g')));
      for (const match of matches) {
        if (match.index === undefined) continue;
        if (pattern.negativeRegex?.test(fullCode)) continue;

        const beforeMatch = fullCode.slice(0, match.index);
        const startLine = beforeMatch.split('\n').length;

        if (!matchedLines.has(startLine)) {
          matchedLines.add(startLine);
          findings.push({
            location: {
              startLine,
              endLine: startLine,
              filePath,
            },
            matchedCode: truncateCode(match[0]),
          });
        }
      }
      continue;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      if (matchedLines.has(lineNum)) continue;
      if (!pattern.regex.test(line)) continue;
      if (pattern.negativeRegex && pattern.negativeRegex.test(line)) continue;

      matchedLines.add(lineNum);
      findings.push({
        location: {
          startLine: lineNum,
          endLine: lineNum,
          filePath,
        },
        matchedCode: truncateCode(line.trim()),
      });
    }
  }

  return findings;
}

function generateAttackScenario(rule: SecurityRule): string {
  const scenarios: Record<string, string> = {
    'CWE-89': "공격자가 입력 필드에 ' OR 1=1; DROP TABLE users; -- 를 입력하여 SQL 쿼리를 조작하고, 전체 데이터베이스를 탈취하거나 삭제할 수 있습니다.",
    'CWE-79': '공격자가 <script>document.cookie</script>와 같은 악성 스크립트를 삽입하여 사용자의 세션 토큰을 탈취하거나, 피싱 페이지로 리다이렉트할 수 있습니다.',
    'CWE-78': '공격자가 ; rm -rf / 또는 && cat /etc/passwd 를 입력하여 서버에서 임의의 시스템 명령을 실행할 수 있습니다.',
    'CWE-94': '공격자가 eval()에 악성 코드를 전달하여 서버에서 임의 코드를 실행하고, 시스템을 완전히 장악할 수 있습니다.',
    'CWE-22': '공격자가 ../../../etc/passwd 경로를 입력하여 서버의 민감한 파일을 읽거나, 웹 루트 외부의 파일에 접근할 수 있습니다.',
    'CWE-918': '공격자가 내부 네트워크 URL(http://169.254.169.254/latest/meta-data/)을 입력하여 클라우드 인스턴스 메타데이터나 내부 서비스에 접근할 수 있습니다.',
    'CWE-798': '소스코드가 유출되면 하드코딩된 시크릿이 함께 노출되어, 공격자가 즉시 시스템에 접근할 수 있습니다.',
    'CWE-352': '공격자가 악성 웹사이트에 자동 제출 폼을 만들어, 로그인된 사용자가 방문하면 의도하지 않은 송금/설정변경을 수행합니다.',
    'CWE-502': '공격자가 조작된 직렬화 데이터를 전송하여 서버에서 임의 코드를 실행할 수 있습니다.',
    'CWE-330': '예측 가능한 난수로 생성된 토큰을 공격자가 추측하여 세션 하이재킹이나 인증 우회에 사용할 수 있습니다.',
    'CWE-327': '취약한 암호화 알고리즘으로 보호된 데이터를 공격자가 복호화하여 민감정보를 탈취할 수 있습니다.',
    'CWE-295': 'TLS 검증이 비활성화된 상태에서 공격자가 중간자 공격(MITM)으로 통신을 가로채 민감정보를 탈취합니다.',
    'CWE-345': '서명 검증 없이 디코딩된 JWT를 조작하여 관리자 권한을 획득할 수 있습니다.',
    'CWE-942': 'CORS가 *로 설정되어 있으면 모든 도메인에서 API를 호출할 수 있어 데이터 탈취에 악용됩니다.',
  };

  return scenarios[rule.cweId] ?? `${rule.titleKo}를 악용하여 시스템 보안을 침해할 수 있습니다.`;
}

function generateImpact(rule: SecurityRule): string {
  const impacts: Record<Severity, string> = {
    critical: '데이터 유출, 시스템 장악, 서비스 전체 중단 가능',
    high: '민감 데이터 노출, 권한 상승, 부분적 시스템 침해 가능',
    medium: '제한적 정보 노출, 설정 오류 악용 가능',
    low: '간접적 보안 위험, 공격 표면 증가',
    info: '보안 개선 권장 사항',
  };
  return impacts[rule.severity];
}

function generateSuggestions(vulns: Vulnerability[], language: Language, framework?: string): string[] {
  const suggestions: string[] = [];
  const categories = new Set(vulns.map((v) => v.cweId));

  if (categories.has('CWE-89') || categories.has('CWE-943')) {
    suggestions.push('ORM 사용을 권장합니다 (예: Prisma, TypeORM, Sequelize)');
  }
  if (categories.has('CWE-79')) {
    suggestions.push('출력 인코딩 라이브러리를 도입하세요 (예: DOMPurify, he)');
  }
  if (categories.has('CWE-798')) {
    suggestions.push('dotenv와 .gitignore를 활용하여 시크릿을 관리하세요');
  }
  if (categories.has('CWE-352')) {
    suggestions.push('CSRF 보호 미들웨어를 적용하세요 (예: csurf, csrf-csrf)');
  }
  if (vulns.some((v) => v.severity === 'critical')) {
    suggestions.push('Critical 취약점이 발견되었습니다. 프로덕션 배포 전 반드시 수정하세요');
  }
  if (framework === 'express' && !categories.has('CWE-693')) {
    suggestions.push('helmet 미들웨어로 보안 헤더를 자동 설정하세요');
  }
  if (language === 'javascript' || language === 'typescript') {
    suggestions.push('입력값 검증 라이브러리를 도입하세요 (예: zod, joi, express-validator)');
  }

  return suggestions;
}
