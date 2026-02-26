import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { generateScanId, nowISO, buildSummary } from '../utils/helpers.js';
import type { ConfigAuditFinding, Severity, Vulnerability } from '../types/index.js';

export const auditConfigSchema = z.object({
  file_path: z.string().describe('감사할 설정 파일 경로 (.env, Dockerfile, docker-compose.yml, nginx.conf 등)'),
});

export type AuditConfigInput = z.infer<typeof auditConfigSchema>;

interface ConfigCheck {
  pattern: RegExp;
  negativePattern?: RegExp;
  severity: Severity;
  issue: string;
  issueKo: string;
  recommendation: string;
  recommendationKo: string;
  fileTypes: string[];
}

const CONFIG_CHECKS: ConfigCheck[] = [
  // .env checks
  {
    pattern: /^(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD)\s*=\s*(?:password|123456|admin|root|test|default)/im,
    severity: 'critical',
    issue: 'Default/weak database password detected',
    issueKo: '기본/취약한 데이터베이스 비밀번호가 감지되었습니다',
    recommendation: 'Use a strong, randomly generated password (32+ chars)',
    recommendationKo: '강력한 랜덤 비밀번호(32자 이상)를 사용하세요',
    fileTypes: ['.env'],
  },
  {
    pattern: /^(?:SECRET_KEY|JWT_SECRET|SESSION_SECRET)\s*=\s*.{1,15}$/im,
    severity: 'high',
    issue: 'Weak secret key (too short)',
    issueKo: '취약한 시크릿 키 (너무 짧음)',
    recommendation: 'Use at least 32 bytes of random data for secrets',
    recommendationKo: '시크릿에 최소 32바이트의 랜덤 데이터를 사용하세요',
    fileTypes: ['.env'],
  },
  {
    pattern: /^DEBUG\s*=\s*(?:true|1|yes)/im,
    severity: 'medium',
    issue: 'Debug mode is enabled',
    issueKo: '디버그 모드가 활성화되어 있습니다',
    recommendation: 'Disable debug mode in production',
    recommendationKo: '프로덕션에서 디버그 모드를 비활성화하세요',
    fileTypes: ['.env'],
  },
  {
    pattern: /^NODE_ENV\s*=\s*development/im,
    severity: 'low',
    issue: 'NODE_ENV set to development',
    issueKo: 'NODE_ENV가 development로 설정되어 있습니다',
    recommendation: 'Ensure NODE_ENV=production in production deployments',
    recommendationKo: '프로덕션 배포 시 NODE_ENV=production을 확인하세요',
    fileTypes: ['.env'],
  },

  // Dockerfile checks
  {
    pattern: /^FROM\s+.*:latest$/im,
    severity: 'medium',
    issue: 'Using :latest tag - non-deterministic builds',
    issueKo: ':latest 태그 사용 - 비결정적 빌드',
    recommendation: 'Pin specific image versions for reproducible builds',
    recommendationKo: '재현 가능한 빌드를 위해 특정 이미지 버전을 고정하세요',
    fileTypes: ['Dockerfile'],
  },
  {
    pattern: /^USER\s+root$/im,
    severity: 'high',
    issue: 'Container runs as root user',
    issueKo: '컨테이너가 root 사용자로 실행됩니다',
    recommendation: 'Create and use a non-root user',
    recommendationKo: 'root가 아닌 사용자를 생성하고 사용하세요',
    fileTypes: ['Dockerfile'],
  },
  {
    pattern: /^(?!.*USER\s+(?!root))/is,
    negativePattern: /USER\s+(?!root)\w+/i,
    severity: 'high',
    issue: 'No USER directive - container runs as root by default',
    issueKo: 'USER 디렉티브 없음 - 컨테이너가 기본적으로 root로 실행됩니다',
    recommendation: 'Add USER directive with non-root user',
    recommendationKo: 'root가 아닌 사용자로 USER 디렉티브를 추가하세요',
    fileTypes: ['Dockerfile'],
  },
  {
    pattern: /COPY\s+\.?\s+\./im,
    negativePattern: /\.dockerignore/,
    severity: 'medium',
    issue: 'COPY . . may include sensitive files (.env, .git)',
    issueKo: 'COPY . . 이 민감한 파일(.env, .git)을 포함할 수 있습니다',
    recommendation: 'Use .dockerignore and copy only needed files',
    recommendationKo: '.dockerignore를 사용하고 필요한 파일만 복사하세요',
    fileTypes: ['Dockerfile'],
  },

  // docker-compose checks
  {
    pattern: /privileged\s*:\s*true/i,
    severity: 'critical',
    issue: 'Privileged mode enabled - full host access',
    issueKo: 'Privileged 모드 활성화 - 호스트 전체 접근 가능',
    recommendation: 'Remove privileged mode. Use specific capabilities instead',
    recommendationKo: 'privileged 모드를 제거하세요. 필요한 capability만 추가하세요',
    fileTypes: ['docker-compose.yml', 'docker-compose.yaml'],
  },
  {
    pattern: /ports:\s*\n\s*-\s*["']?0\.0\.0\.0:(\d+)/im,
    severity: 'medium',
    issue: 'Port bound to 0.0.0.0 (all interfaces)',
    issueKo: '포트가 0.0.0.0(모든 인터페이스)에 바인딩됩니다',
    recommendation: 'Bind to 127.0.0.1 for internal services',
    recommendationKo: '내부 서비스는 127.0.0.1에 바인딩하세요',
    fileTypes: ['docker-compose.yml', 'docker-compose.yaml'],
  },

  // General config checks
  {
    pattern: /(?:password|secret|key|token)\s*[:=]\s*['"](?:admin|password|123456|test|default|changeme)['"]/i,
    severity: 'critical',
    issue: 'Default/weak credentials in configuration',
    issueKo: '설정에 기본/취약한 인증정보가 포함되어 있습니다',
    recommendation: 'Use strong, unique credentials from environment variables',
    recommendationKo: '환경변수에서 강력하고 고유한 인증정보를 사용하세요',
    fileTypes: ['.env', '.yml', '.yaml', '.json', '.conf'],
  },
];

function runConfigChecks(content: string, fileName: string, fileSource: string): ConfigAuditFinding[] {
  const fileExt = fileName.includes('Dockerfile')
    ? 'Dockerfile'
    : fileName.slice(fileName.lastIndexOf('.')).toLowerCase();

  const applicableChecks = CONFIG_CHECKS.filter((check) =>
    check.fileTypes.some((ft) => fileName.includes(ft) || fileExt === ft || fileName === ft)
  );

  const findings: ConfigAuditFinding[] = [];
  const contentLines = content.split('\n');

  for (const check of applicableChecks) {
    if (check.negativePattern && check.negativePattern.test(content)) continue;

    const checkFindingsBefore = findings.length;

    for (let i = 0; i < contentLines.length; i++) {
      if (check.pattern.test(contentLines[i])) {
        findings.push({
          file: fileSource,
          line: i + 1,
          key: contentLines[i].split(/[:=]/)[0]?.trim() ?? '',
          severity: check.severity,
          issue: check.issue,
          issueKo: check.issueKo,
          recommendation: check.recommendation,
          recommendationKo: check.recommendationKo,
        });
      }
    }

    if (check.pattern.flags.includes('s') || check.pattern.flags.includes('m')) {
      if (check.pattern.test(content) && findings.length === checkFindingsBefore) {
        findings.push({
          file: fileSource,
          severity: check.severity,
          key: '',
          issue: check.issue,
          issueKo: check.issueKo,
          recommendation: check.recommendation,
          recommendationKo: check.recommendationKo,
        });
      }
    }
  }

  return findings;
}

function formatAuditResult(findings: ConfigAuditFinding[], displayName: string, fileSource: string) {
  const vulns: Vulnerability[] = findings.map((f, i) => ({
    id: `CFG-${String(i + 1).padStart(3, '0')}`,
    ruleId: 'SCG-MCF-CFG',
    title: f.issue,
    titleKo: f.issueKo,
    severity: f.severity,
    confidence: 'high' as const,
    category: 'A05:2021-Security Misconfiguration',
    cweId: 'CWE-16',
    location: { startLine: f.line ?? 0, endLine: f.line ?? 0, filePath: f.file },
    matchedCode: f.key,
    description: f.issue,
    descriptionKo: f.issueKo,
    remediation: {
      description: f.recommendation,
      descriptionKo: f.recommendationKo,
      references: [],
    },
  }));

  const summary = buildSummary(vulns);
  const lines: string[] = [];

  lines.push(`## 🔧 설정 파일 보안 감사: ${displayName}`);
  lines.push('');
  lines.push(`| 항목 | 값 |`);
  lines.push(`|---|---|`);
  lines.push(`| 파일 | \`${fileSource}\` |`);
  lines.push(`| 발견 이슈 | **${findings.length}개** |`);
  lines.push(`| 위험 점수 | **${summary.riskScore}/10** |`);
  lines.push('');

  if (findings.length === 0) {
    lines.push('### ✅ 설정 파일에서 보안 이슈가 발견되지 않았습니다.');
  } else {
    for (const f of findings) {
      const badge = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' }[f.severity];
      lines.push(`### ${badge} ${f.issueKo}`);
      if (f.line) lines.push(`- 위치: ${f.line}번째 줄`);
      if (f.key) lines.push(`- 키: \`${f.key}\``);
      lines.push(`- 심각도: ${f.severity.toUpperCase()}`);
      lines.push(`- **권장**: ${f.recommendationKo}`);
      lines.push('');
    }
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
  };
}

export function handleAuditConfig(input: AuditConfigInput) {
  const filePath = resolve(input.file_path);
  let content: string;

  try {
    content = readFileSync(filePath, 'utf-8');
  } catch (err) {
    return {
      content: [
        {
          type: 'text' as const,
          text: `❌ 파일을 읽을 수 없습니다: ${filePath}\n에러: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
    };
  }

  const fileName = basename(filePath);
  const findings = runConfigChecks(content, fileName, filePath);
  return formatAuditResult(findings, fileName, filePath);
}

export function handleAuditConfigContent(content: string, configType: string) {
  const typeToFileName: Record<string, string> = {
    dockerfile: 'Dockerfile',
    'docker-compose': 'docker-compose.yml',
    env: '.env',
  };
  const fileName = typeToFileName[configType] ?? '.env';
  const findings = runConfigChecks(content, fileName, `(inline ${configType})`);
  return formatAuditResult(findings, fileName, `(inline ${configType})`);
}
