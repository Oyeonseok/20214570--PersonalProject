import { z } from 'zod';
import { getVulnDetail, extractCveId, extractGhsaId, type OsvVulnDetail } from '../services/osv-client.js';
import { getCveDetail, cvssToSeverity } from '../services/nvd-client.js';
import { getPatternsByCve, getPatternsByPackage, scanCodeForCvePatterns } from '../services/cve-code-patterns.js';
import { getKnowledgeByCwe, findKnowledgeForCweIds } from '../knowledge/portswigger-remediation.js';

export const searchCveSchema = z.object({
  query: z.string().describe('CVE ID (CVE-XXXX-XXXXX), GHSA ID (GHSA-xxxx-xxxx-xxxx), 또는 패키지명'),
  version: z.string().optional().describe('패키지 버전 (패키지명 검색 시)'),
  code_snippet: z.string().optional().describe('취약 패턴 검사할 코드 스니펫'),
});

export type SearchCveInput = z.infer<typeof searchCveSchema>;

export async function handleSearchCve(input: SearchCveInput) {
  const { query, code_snippet } = input;
  const lines: string[] = [];

  const isCve = /^CVE-\d{4}-\d+$/i.test(query);
  const isGhsa = /^GHSA-[\w-]+$/i.test(query);

  if (isCve || isGhsa) {
    lines.push(...(await searchByVulnId(query, code_snippet)));
  } else {
    lines.push(...(await searchByPackage(query, input.version, code_snippet)));
  }

  if (lines.length === 0) {
    lines.push(`⚠️ "${query}"에 대한 취약점 정보를 찾을 수 없습니다.`);
  }

  return { content: [{ type: 'text' as const, text: lines.join('\n') }] };
}

async function searchByVulnId(vulnId: string, codeSnippet?: string): Promise<string[]> {
  const lines: string[] = [];

  let osvDetail: OsvVulnDetail | null = null;
  try {
    osvDetail = await getVulnDetail(vulnId);
  } catch {
    // try NVD directly if OSV fails
  }

  const cveId = osvDetail ? extractCveId(osvDetail) ?? vulnId : vulnId;
  const ghsaId = osvDetail ? extractGhsaId(osvDetail) : undefined;

  let nvdCvss: { baseScore: number; baseSeverity: string; vectorString: string } | undefined;
  let nvdCweIds: string[] = [];
  let nvdDescription = '';

  if (cveId.startsWith('CVE-')) {
    try {
      const nvd = await getCveDetail(cveId);
      if (nvd) {
        nvdCvss = nvd.cvss;
        nvdCweIds = nvd.cweIds;
        nvdDescription = nvd.description;
      }
    } catch {
      // NVD unavailable
    }
  }

  lines.push(`## 🔍 취약점 상세: ${vulnId}`);
  lines.push('');
  lines.push('| 항목 | 값 |');
  lines.push('|---|---|');
  if (cveId) lines.push(`| CVE | ${cveId} |`);
  if (ghsaId) lines.push(`| GHSA | ${ghsaId} |`);
  if (nvdCvss) {
    lines.push(`| CVSS ${nvdCvss.baseSeverity ? `(${nvdCvss.baseSeverity})` : ''} | **${nvdCvss.baseScore}** |`);
    lines.push(`| Vector | \`${nvdCvss.vectorString}\` |`);
    lines.push(`| 심각도 | ${cvssToSeverity(nvdCvss.baseScore).toUpperCase()} |`);
  }
  if (nvdCweIds.length > 0) lines.push(`| CWE | ${nvdCweIds.join(', ')} |`);
  lines.push('');

  const description = nvdDescription || osvDetail?.summary || osvDetail?.details?.slice(0, 500) || '';
  if (description) {
    lines.push('### 📖 설명');
    lines.push('');
    lines.push(description);
    lines.push('');
  }

  if (osvDetail?.affected && osvDetail.affected.length > 0) {
    lines.push('### 📦 영향받는 패키지');
    lines.push('');
    for (const aff of osvDetail.affected.slice(0, 5)) {
      const fixedVersions = aff.ranges?.flatMap((r) => r.events.filter((e) => e.fixed).map((e) => e.fixed!)) ?? [];
      lines.push(`- **${aff.package.name}** (${aff.package.ecosystem})`);
      if (fixedVersions.length > 0) lines.push(`  - 패치 버전: ${fixedVersions.join(', ')}`);
    }
    lines.push('');
  }

  const codePattern = getPatternsByCve(cveId);
  if (codePattern) {
    lines.push('### 🔧 코드 수정 가이드');
    lines.push('');
    lines.push(`**위험:** ${codePattern.descriptionKo}`);
    lines.push('');
    lines.push(`**수정 방안:** ${codePattern.codeRemediationKo}`);
    lines.push('');
    lines.push('**안전한 코드 예시:**');
    lines.push('```');
    lines.push(codePattern.safeAlternative);
    lines.push('```');
    lines.push('');

    if (codeSnippet) {
      const findings = scanCodeForCvePatterns(codeSnippet, [codePattern]);
      if (findings.length > 0) {
        lines.push('### ⚠️ 제공된 코드에서 위험 패턴 발견:');
        lines.push('');
        for (const f of findings) {
          lines.push(`- **Line ${f.line}:** \`${f.matchedCode}\``);
          lines.push(`  - ${f.pattern.codeRemediationKo}`);
        }
        lines.push('');
      }
    }
  }

  const allCweIds = [...nvdCweIds, ...(codePattern ? [codePattern.cweId] : [])];
  const psKnowledge = findKnowledgeForCweIds([...new Set(allCweIds)]);
  if (psKnowledge.length > 0) {
    for (const ps of psKnowledge) {
      lines.push(`### 🛡️ 방어 기법: ${ps.titleKo}`);
      lines.push('');
      lines.push(`**공격 원리:** ${ps.attackMechanismKo}`);
      lines.push('');
      lines.push('**방어 기법:**');
      for (const tech of ps.preventionTechniquesKo) {
        lines.push(`- ${tech}`);
      }
      lines.push('');
      lines.push('**개발자 흔한 실수:**');
      for (const mistake of ps.commonMistakesKo) {
        lines.push(`- ❌ ${mistake}`);
      }
      lines.push('');
      lines.push(`📚 참고: ${ps.portswiggerUrl}`);
      lines.push('');
    }
  }

  const refs: string[] = [];
  if (cveId) refs.push(`https://nvd.nist.gov/vuln/detail/${cveId}`);
  if (ghsaId) refs.push(`https://github.com/advisories/${ghsaId}`);
  if (osvDetail?.references) {
    for (const r of osvDetail.references.slice(0, 5)) refs.push(r.url);
  }
  if (refs.length > 0) {
    lines.push('### 📚 참고 자료');
    for (const ref of [...new Set(refs)]) lines.push(`- ${ref}`);
  }

  return lines;
}

async function searchByPackage(packageName: string, version: string | undefined, codeSnippet?: string): Promise<string[]> {
  const lines: string[] = [];
  lines.push(`## 📦 패키지 취약점 검색: ${packageName}${version ? `@${version}` : ''}`);
  lines.push('');

  const patterns = getPatternsByPackage(packageName);

  if (patterns.length === 0) {
    lines.push(`로컬 CVE 패턴 DB에 "${packageName}"의 알려진 취약점이 없습니다.`);
    lines.push('OSV.dev에서 실시간 검색을 시도합니다...');
    lines.push('');
  }

  for (const pattern of patterns) {
    lines.push(`### ${pattern.cveId} -- ${pattern.description}`);
    lines.push('');
    lines.push(`- CWE: ${pattern.cweId}`);
    lines.push(`- **위험:** ${pattern.descriptionKo}`);
    lines.push(`- **수정:** ${pattern.codeRemediationKo}`);

    const ps = getKnowledgeByCwe(pattern.cweId);
    if (ps) {
      lines.push(`- **방어 기법:** ${ps.preventionTechniquesKo[0]}`);
      lines.push(`- 📚 ${ps.portswiggerUrl}`);
    }
    lines.push('');
  }

  if (codeSnippet && patterns.length > 0) {
    const findings = scanCodeForCvePatterns(codeSnippet, patterns);
    if (findings.length > 0) {
      lines.push('### ⚠️ 코드에서 위험 패턴 발견:');
      lines.push('');
      for (const f of findings) {
        lines.push(`- **${f.cveId}** Line ${f.line}: \`${f.matchedCode}\``);
        lines.push(`  - ${f.pattern.codeRemediationKo}`);
      }
    } else {
      lines.push('### ✅ 코드에서 알려진 위험 패턴이 발견되지 않았습니다.');
    }
  }

  return lines;
}
