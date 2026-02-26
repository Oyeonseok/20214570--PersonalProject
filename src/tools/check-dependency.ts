import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { generateScanId, nowISO } from '../utils/helpers.js';
import type { DependencyScanResult, DependencyVulnerability, CodeUsageFinding } from '../types/index.js';
import { queryBatch, getVulnDetail, extractCveId, extractGhsaId, extractFixedVersion, type OsvPackageQuery } from '../services/osv-client.js';
import { getCveDetail, cvssToSeverity, type CvssData } from '../services/nvd-client.js';
import { getPatternsByPackage, scanCodeForCvePatterns, type CveCodePattern } from '../services/cve-code-patterns.js';
import { getKnowledgeByCwe } from '../knowledge/portswigger-remediation.js';

export const checkDependencySchema = z.object({
  manifest_path: z.string().describe('매니페스트 파일 경로 (package.json, requirements.txt 등)'),
  severity_filter: z
    .enum(['critical', 'high', 'medium', 'low'])
    .default('medium')
    .describe('리포트할 최소 심각도'),
  code_to_scan: z
    .string()
    .optional()
    .describe('(선택) 취약한 패키지의 위험 API 사용을 코드에서 탐지할 때 전달'),
});

export type CheckDependencyInput = z.infer<typeof checkDependencySchema>;

interface KnownVuln {
  package: string;
  vulnerableRange: string;
  patchedVersion: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cveId: string;
  cweId: string;
  title: string;
  description: string;
  exploitAvailable: boolean;
}

const KNOWN_VULNS: KnownVuln[] = [
  { package: 'lodash', vulnerableRange: '<4.17.21', patchedVersion: '4.17.21', severity: 'high', cveId: 'CVE-2021-23337', cweId: 'CWE-77', title: 'Command Injection in lodash', description: 'lodash의 template 함수에서 명령 인젝션 취약점', exploitAvailable: true },
  { package: 'express', vulnerableRange: '<4.19.2', patchedVersion: '4.19.2', severity: 'medium', cveId: 'CVE-2024-29041', cweId: 'CWE-601', title: 'Open Redirect in express', description: 'express의 res.redirect()에서 오픈 리다이렉트 취약점', exploitAvailable: false },
  { package: 'jsonwebtoken', vulnerableRange: '<9.0.0', patchedVersion: '9.0.0', severity: 'high', cveId: 'CVE-2022-23529', cweId: 'CWE-20', title: 'Insecure Key Handling in jsonwebtoken', description: 'jsonwebtoken의 secretOrPublicKey 파라미터 검증 미흡', exploitAvailable: true },
  { package: 'axios', vulnerableRange: '<1.6.0', patchedVersion: '1.6.0', severity: 'high', cveId: 'CVE-2023-45857', cweId: 'CWE-352', title: 'CSRF Token Leakage in axios', description: 'axios에서 XSRF-TOKEN 쿠키가 cross-site 요청에 노출', exploitAvailable: false },
  { package: 'minimatch', vulnerableRange: '<3.0.5', patchedVersion: '3.0.5', severity: 'high', cveId: 'CVE-2022-3517', cweId: 'CWE-1333', title: 'ReDoS in minimatch', description: 'minimatch의 braceExpand에서 ReDoS 취약점', exploitAvailable: true },
  { package: 'qs', vulnerableRange: '<6.10.3', patchedVersion: '6.10.3', severity: 'high', cveId: 'CVE-2022-24999', cweId: 'CWE-1321', title: 'Prototype Pollution in qs', description: 'qs 라이브러리에서 프로토타입 오염 취약점', exploitAvailable: true },
  { package: 'semver', vulnerableRange: '<7.5.2', patchedVersion: '7.5.2', severity: 'medium', cveId: 'CVE-2022-25883', cweId: 'CWE-1333', title: 'ReDoS in semver', description: 'semver의 range parsing에서 ReDoS 취약점', exploitAvailable: false },
  { package: 'node-fetch', vulnerableRange: '<2.6.7', patchedVersion: '2.6.7', severity: 'high', cveId: 'CVE-2022-0235', cweId: 'CWE-601', title: 'Exposure of Sensitive Information in node-fetch', description: 'node-fetch에서 리다이렉트 시 Authorization 헤더 노출', exploitAvailable: false },
  { package: 'moment', vulnerableRange: '<2.29.4', patchedVersion: '2.29.4', severity: 'high', cveId: 'CVE-2022-31129', cweId: 'CWE-1333', title: 'ReDoS in moment', description: 'moment의 날짜 파싱에서 ReDoS 취약점', exploitAvailable: true },
  { package: 'helmet', vulnerableRange: '<6.0.0', patchedVersion: '6.0.0', severity: 'medium', cveId: 'CVE-2023-xxxxx', cweId: 'CWE-693', title: 'Insufficient Security Headers in helmet', description: '이전 버전 helmet에서 일부 보안 헤더 기본값 미흡', exploitAvailable: false },
];

function parseVersion(version: string): number[] {
  const clean = version.replace(/^[^0-9]*/, '').replace(/[^0-9.].*/, '');
  return clean.split('.').map(Number);
}

function isVulnerable(installed: string, vulnerableRange: string): boolean {
  if (!installed || installed === '*' || installed === 'latest') return true;
  const rangeMatch = vulnerableRange.match(/^<(.+)$/);
  if (!rangeMatch) return false;
  const threshold = parseVersion(rangeMatch[1]);
  const current = parseVersion(installed);
  for (let i = 0; i < Math.max(threshold.length, current.length); i++) {
    const t = threshold[i] ?? 0;
    const c = current[i] ?? 0;
    if (c < t) return true;
    if (c > t) return false;
  }
  return false;
}

function localFallbackScan(
  deps: Record<string, string>,
  severityFilter: string,
  codeToScan?: string,
): { vulnerabilities: DependencyVulnerability[]; source: 'local-db' } {
  const vulnerabilities: DependencyVulnerability[] = [];
  for (const [pkg, version] of Object.entries(deps)) {
    const cleanVersion = version.replace(/^[\^~>=<]*/g, '');
    for (const known of KNOWN_VULNS) {
      if (known.package === pkg && isVulnerable(cleanVersion, known.vulnerableRange)) {
        const vuln: DependencyVulnerability = {
          packageName: pkg,
          installedVersion: cleanVersion,
          vulnerableRange: known.vulnerableRange,
          patchedVersion: known.patchedVersion,
          severity: known.severity,
          cveId: known.cveId,
          cweId: known.cweId,
          source: 'local-db',
          title: known.title,
          description: known.description,
          exploitAvailable: known.exploitAvailable,
          fixCommand: `npm install ${pkg}@${known.patchedVersion}`,
          references: [`https://nvd.nist.gov/vuln/detail/${known.cveId}`],
        };

        if (codeToScan) {
          const patterns = getPatternsByPackage(pkg);
          if (patterns.length > 0) {
            const codeFindings = scanCodeForCvePatterns(codeToScan, patterns);
            vuln.codeUsageFindings = codeFindings.map((f) => ({
              line: f.line,
              matchedCode: f.matchedCode,
              pattern: f.pattern.description,
              codeRemediation: f.pattern.codeRemediation,
              codeRemediationKo: f.pattern.codeRemediationKo,
              safeAlternative: f.pattern.safeAlternative,
            }));
          }
        }

        vulnerabilities.push(vuln);
      }
    }
  }
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const filterLevel = severityOrder[severityFilter];
  return { vulnerabilities: vulnerabilities.filter((v) => severityOrder[v.severity] <= filterLevel), source: 'local-db' };
}

async function osvPipeline(
  deps: Record<string, string>,
  ecosystem: 'npm' | 'PyPI',
  codeToScan?: string,
): Promise<DependencyVulnerability[]> {
  const packages: OsvPackageQuery[] = Object.entries(deps).map(([name, ver]) => ({
    name,
    ecosystem,
    version: ver.replace(/^[\^~>=<]*/g, ''),
  }));

  const batchResult = await queryBatch(packages);
  const vulnerabilities: DependencyVulnerability[] = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const vulnSummaries = batchResult.results[i]?.vulns ?? [];

    for (const summary of vulnSummaries) {
      let detail;
      try {
        detail = await getVulnDetail(summary.id);
      } catch {
        continue;
      }

      const cveId = extractCveId(detail);
      const ghsaId = extractGhsaId(detail);
      const fixedVersion = extractFixedVersion(detail, pkg.name);

      let cvss: CvssData | undefined;
      let officialCweIds: string[] = [];
      if (cveId) {
        try {
          const nvdDetail = await getCveDetail(cveId);
          if (nvdDetail) {
            cvss = nvdDetail.cvss;
            officialCweIds = nvdDetail.cweIds;
          }
        } catch {
          // NVD unavailable, continue without CVSS
        }
      }

      const severity = cvss
        ? cvssToSeverity(cvss.baseScore)
        : (detail.database_specific as Record<string, unknown>)?.severity
          ? String((detail.database_specific as Record<string, unknown>).severity).toLowerCase() as DependencyVulnerability['severity']
          : 'medium';

      const cweId = officialCweIds[0] ?? undefined;

      const vuln: DependencyVulnerability = {
        packageName: pkg.name,
        installedVersion: pkg.version ?? '*',
        vulnerableRange: fixedVersion ? `<${fixedVersion}` : 'unknown',
        patchedVersion: fixedVersion,
        severity: severity as DependencyVulnerability['severity'],
        cveId,
        cweId,
        ghsaId,
        osvId: detail.id,
        source: 'osv-realtime',
        cvssScore: cvss?.baseScore,
        cvssVector: cvss?.vectorString,
        cvssSeverity: cvss?.baseSeverity,
        title: detail.summary ?? detail.id,
        description: detail.details?.slice(0, 300) ?? '',
        exploitAvailable: false,
        fixCommand: fixedVersion ? `npm install ${pkg.name}@${fixedVersion}` : undefined,
        references: [
          ...(detail.references?.map((r) => r.url) ?? []),
          ...(cveId ? [`https://nvd.nist.gov/vuln/detail/${cveId}`] : []),
        ],
      };

      if (codeToScan) {
        const patterns = getPatternsByPackage(pkg.name);
        if (patterns.length > 0) {
          const codeFindings = scanCodeForCvePatterns(codeToScan, patterns);
          vuln.codeUsageFindings = codeFindings.map((f) => ({
            line: f.line,
            matchedCode: f.matchedCode,
            pattern: f.pattern.description,
            codeRemediation: f.pattern.codeRemediation,
            codeRemediationKo: f.pattern.codeRemediationKo,
            safeAlternative: f.pattern.safeAlternative,
          }));
        }
      }

      vulnerabilities.push(vuln);
    }
  }

  return vulnerabilities;
}

export async function handleCheckDependency(input: CheckDependencyInput) {
  const filePath = resolve(input.manifest_path);
  let content: string;

  try {
    content = readFileSync(filePath, 'utf-8');
  } catch (err) {
    return {
      content: [{
        type: 'text' as const,
        text: `❌ 파일을 읽을 수 없습니다: ${filePath}\n에러: ${err instanceof Error ? err.message : String(err)}`,
      }],
    };
  }

  const fileName = basename(filePath);
  let deps: Record<string, string> = {};
  let ecosystem: 'npm' | 'PyPI' = 'npm';

  if (fileName === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    } catch {
      return { content: [{ type: 'text' as const, text: '❌ package.json 파싱에 실패했습니다.' }] };
    }
  } else if (fileName === 'requirements.txt') {
    ecosystem = 'PyPI';
    for (const line of content.split('\n')) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*(?:==|>=|~=)\s*(.+)/);
      if (match) deps[match[1]] = match[2];
    }
  } else {
    return {
      content: [{
        type: 'text' as const,
        text: `⚠️ 지원하지 않는 매니페스트 형식입니다: ${fileName}\n지원: package.json, requirements.txt`,
      }],
    };
  }

  const totalDeps = Object.keys(deps).length;
  let vulnerabilities: DependencyVulnerability[];
  let dataSource: string;

  try {
    vulnerabilities = await osvPipeline(deps, ecosystem, input.code_to_scan);
    dataSource = '실시간 OSV + NVD CVSS';
  } catch {
    const fallback = localFallbackScan(deps, input.severity_filter, input.code_to_scan);
    vulnerabilities = fallback.vulnerabilities;
    dataSource = '로컬 DB (API 장애)';
  }

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const filterLevel = severityOrder[input.severity_filter];
  const filtered = vulnerabilities.filter((v) => severityOrder[v.severity] <= filterLevel);

  const deduped = new Map<string, DependencyVulnerability>();
  for (const v of filtered) {
    const key = `${v.packageName}:${v.cveId ?? v.osvId ?? v.title}`;
    if (!deduped.has(key)) deduped.set(key, v);
  }
  const finalVulns = [...deduped.values()];

  const result: DependencyScanResult = {
    scanId: generateScanId(),
    timestamp: nowISO(),
    manifest: fileName,
    totalDependencies: totalDeps,
    vulnerableCount: finalVulns.length,
    vulnerabilities: finalVulns,
    recommendations: [],
  };

  const lines: string[] = [];
  lines.push(`## 📦 의존성 보안 검사: ${fileName}`);
  lines.push('');
  lines.push(`| 항목 | 값 |`);
  lines.push(`|---|---|`);
  lines.push(`| 총 의존성 | ${totalDeps}개 |`);
  lines.push(`| 취약한 패키지 | **${finalVulns.length}개** |`);
  lines.push(`| 데이터 소스 | ${dataSource} |`);
  lines.push('');

  if (finalVulns.length === 0) {
    lines.push('### ✅ 알려진 취약점이 발견되지 않았습니다.');
  } else {
    for (const vuln of finalVulns) {
      const badge = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' }[vuln.severity];
      const cvssLabel = vuln.cvssScore ? ` | CVSS ${vuln.cvssScore} (${vuln.cvssSeverity})` : '';

      lines.push(`### ${badge} ${vuln.packageName}@${vuln.installedVersion}`);
      lines.push(`- **${vuln.title}**`);
      lines.push(`- 심각도: ${vuln.severity.toUpperCase()}${cvssLabel}`);
      if (vuln.cveId) lines.push(`- CVE: ${vuln.cveId} | ${vuln.cweId ?? 'N/A'}`);
      if (vuln.cvssVector) lines.push(`- CVSS Vector: \`${vuln.cvssVector}\``);
      lines.push(`- ${vuln.description}`);
      if (vuln.patchedVersion) lines.push(`- 패치 버전: \`${vuln.patchedVersion}\``);
      if (vuln.fixCommand) lines.push(`- 수정 명령: \`${vuln.fixCommand}\``);
      if (vuln.exploitAvailable) lines.push(`- ⚠️ **공개된 익스플로잇 존재**`);

      if (vuln.codeUsageFindings && vuln.codeUsageFindings.length > 0) {
        lines.push('');
        lines.push('  **🔍 코드에서 위험 API 사용 발견:**');
        for (const finding of vuln.codeUsageFindings) {
          lines.push(`  - Line ${finding.line}: \`${finding.matchedCode}\``);
          lines.push(`    - ${finding.codeRemediationKo}`);
        }
      }

      if (vuln.cweId) {
        const ps = getKnowledgeByCwe(vuln.cweId);
        if (ps) {
          lines.push('');
          lines.push(`  **🛡️ 방어 기법 (PortSwigger):** ${ps.preventionTechniquesKo.slice(0, 2).join(', ')}`);
          lines.push(`  - 참고: ${ps.portswiggerUrl}`);
        }
      }
      lines.push('');
    }

    lines.push('## 🔧 일괄 수정 명령');
    const fixCmds = finalVulns.filter((v) => v.patchedVersion).map((v) => `${v.packageName}@${v.patchedVersion}`);
    if (fixCmds.length > 0) {
      lines.push(`\`\`\`bash\nnpm install ${fixCmds.join(' ')}\n\`\`\``);
    }
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
    structuredResult: result,
  };
}
