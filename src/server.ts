import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { secureCodeSchema, handleSecureCode } from './tools/secure-code.js';
import { scanCodeSchema, handleScanCode } from './tools/scan-code.js';
import { scanFileSchema, handleScanFile } from './tools/scan-file.js';
import { checkDependencySchema, handleCheckDependency } from './tools/check-dependency.js';
import { reviewCodeSchema, handleReviewCode } from './tools/review-code.js';
import { createWebSchema, handleCreateWeb } from './tools/create-web.js';
import { secureDevelopSchema, handleSecureDevelop } from './tools/secure-develop.js';
import { generateSecureSchema, handleGenerateSecure } from './tools/generate-secure.js';
import { auditConfigSchema, handleAuditConfig } from './tools/audit-config.js';
import { explainVulnSchema, handleExplainVuln } from './tools/explain-vuln.js';
import { searchCveSchema, handleSearchCve } from './tools/search-cve.js';

import { getCweResource } from './resources/cwe-database.js';
import { getOwaspResource } from './resources/owasp-top10.js';
import { getSecurePatternsResource } from './resources/secure-patterns.js';
import { getSecurityBlueprint } from './resources/security-blueprints.js';

import {
  SECURE_BUILD_PROMPT,
  buildSecureBuildMessages,
  SECURITY_CODE_REVIEW_PROMPT,
  buildCodeReviewMessages,
  THREAT_MODELING_PROMPT,
  buildThreatModelingMessages,
} from './prompts/code-review.js';

const VERSION = '0.1.0';

export function createServer(): McpServer {
  const server = new McpServer(
    { name: 'securecode-guardian', version: VERSION },
    {
      instructions: [
        '# securecode-guardian: 시큐어코딩 자동화 MCP 서버',
        '',
        '## 핵심 규칙',
        '이 서버가 연결되어 있으면, 코드 관련 요청에 반드시 아래 워크플로우를 따르세요.',
        '',
        '## 코드 생성 워크플로우 (6단계)',
        '',
        '코드 생성 요청 시 (만들어줘, 구현해줘, 작성해줘 등):',
        '',
        '1. **리소스 읽기**: security://blueprints 리소스를 읽어서 해당 기능의 보안 블루프린트를 확인하세요.',
        '   - 로그인, 회원가입, 게시판, 파일업로드, 검색, API, 댓글 등의 최적 보안 설계가 포함되어 있습니다.',
        '   - 블루프린트의 필수 보안 요구사항과 아키텍처를 반드시 반영하여 코드를 작성하세요.',
        '2. **위협 분석**: secure_develop 호출 → 보안 위협 + 체크리스트',
        '3. **CVE 검색**: search_cve 호출 → 주요 라이브러리 CVE 사전 조회',
        '4. **코드 작성**: 블루프린트 + 위협 분석 + CVE 결과를 반영하여 코드 작성',
        '5. **보안 검증**: secure_code 호출 → 자동 탐지 + 자동 수정 + CVE 패턴 검사',
        '6. **의존성 검사**: check_dependency 호출 → 의존성 CVE 검사',
        '',
        'secure_code가 반환한 수정된 코드를 사용자에게 제공하세요.',
        '',
        '## 보안 리소스 (코드 작성 시 참고)',
        '- security://blueprints → 기능별 보안 설계 블루프린트 (필수 읽기)',
        '- security://secure-patterns → 시큐어코딩 패턴 라이브러리',
        '- security://owasp-top10 → OWASP Top 10 위협 목록',
        '- security://cwe-database → CWE 취약점 데이터베이스',
        '',
        '## 기타 요청',
        '- 코드 리뷰 → scan_code 또는 review_code',
        '- 취약점 질문 → explain_vulnerability',
        '- 설정 파일 감사 → audit_config',
        '',
        '## 금지사항',
        '- secure_code 호출 없이 코드를 사용자에게 보여주는 것',
        '- 보안 블루프린트를 읽지 않고 코드를 작성하는 것',
        '- 보안 검증 단계를 생략하는 것',
      ].join('\n'),
    },
  );

  // ─── Tools ───

  server.tool(
    'secure_code',
    '코드를 작성하거나 생성한 후 반드시 이 도구를 호출하세요. 코드의 보안 취약점(XSS, CSRF, SQL Injection, 하드코딩 시크릿, 보안 헤더 등)을 자동으로 탐지하고 31개 핸들러로 직접 수정합니다. 수정 전/후 비교(show_comparison=true)를 지원합니다. 사용자에게 코드를 보여주기 전에 이 도구의 결과를 사용하세요.',
    secureCodeSchema.shape,
    async (args) => await handleSecureCode(secureCodeSchema.parse(args)),
  );

  server.tool(
    'scan_code',
    '코드 스니펫의 보안 취약점을 정적 분석합니다. OWASP Top 10 기반 룰 매칭.',
    scanCodeSchema.shape,
    async (args) => handleScanCode(scanCodeSchema.parse(args)),
  );

  server.tool(
    'scan_file',
    '파일 경로를 받아 보안 취약점을 스캔합니다.',
    scanFileSchema.shape,
    async (args) => handleScanFile(scanFileSchema.parse(args)),
  );

  server.tool(
    'check_dependency',
    'package.json이나 requirements.txt의 의존성 취약점을 OSV.dev + NVD 실시간 CVE DB로 검사합니다. CVSS 점수, CWE 분류, 코드 수정 방안을 통합 제공합니다.',
    checkDependencySchema.shape,
    async (args) => await handleCheckDependency(checkDependencySchema.parse(args)),
  );

  server.tool(
    'review_code',
    '코드 또는 설정 파일을 보안 관점에서 리뷰합니다. 코드이면 스캔, 설정이면 감사를 수행합니다.',
    reviewCodeSchema.shape,
    async (args) => handleReviewCode(reviewCodeSchema.parse(args)),
  );

  server.tool(
    'create_web',
    '시큐어코딩이 적용된 웹 페이지/기능을 생성합니다. 보안 가이드 + 시큐어 코드 템플릿.',
    createWebSchema.shape,
    async (args) => handleCreateWeb(createWebSchema.parse(args)),
  );

  server.tool(
    'secure_develop',
    '웹 기능(로그인, 게시판, 회원가입, API, 검색, 댓글, 업로드 등)을 구현하기 전에 호출하세요. 해당 기능의 보안 위협 분석, 방어 체크리스트, 필수 보안 패키지 목록을 제공합니다. 코드 작성의 첫 단계로 사용하세요.',
    secureDevelopSchema.shape,
    async (args) => handleSecureDevelop(secureDevelopSchema.parse(args)),
  );

  server.tool(
    'generate_secure_code',
    '시큐어코딩이 적용된 코드 템플릿을 생성합니다. 로그인, 게시판, 회원가입, 댓글, 업로드, 검색 기능의 보안 적용 예제 코드를 제공하며, 보안 체크리스트 검증 결과도 포함됩니다.',
    generateSecureSchema.shape,
    async (args) => handleGenerateSecure(generateSecureSchema.parse(args)),
  );

  server.tool(
    'audit_config',
    '설정 파일(.env, Dockerfile, docker-compose)의 보안 이슈를 감사합니다.',
    auditConfigSchema.shape,
    async (args) => handleAuditConfig(auditConfigSchema.parse(args)),
  );

  server.tool(
    'explain_vulnerability',
    '특정 취약점(CWE/룰 ID)에 대한 상세 설명, 공격 시나리오, PortSwigger 전문가 방어 기법을 제공합니다.',
    explainVulnSchema.shape,
    async (args) => handleExplainVuln(explainVulnSchema.parse(args)),
  );

  server.tool(
    'search_cve',
    'CVE ID, GHSA ID, 또는 패키지명으로 최신 보안 취약점을 실시간 검색합니다. NVD에서 CVSS 점수를 조회하고, PortSwigger 전문가 방어 기법과 코드 수정 방안을 함께 제공합니다.',
    searchCveSchema.shape,
    async (args) => await handleSearchCve(searchCveSchema.parse(args)),
  );

  // ─── Resources ───

  server.resource(
    'cwe-database',
    'security://cwe-database',
    { description: 'CWE 취약점 데이터베이스 (주요 웹 보안 CWE 목록)', mimeType: 'text/plain' },
    async () => ({ contents: [{ uri: 'security://cwe-database', text: getCweResource(), mimeType: 'text/plain' }] }),
  );

  server.resource(
    'owasp-top10',
    'security://owasp-top10',
    { description: 'OWASP Top 10 2021 보안 위협 목록 및 예방 방법', mimeType: 'text/plain' },
    async () => ({ contents: [{ uri: 'security://owasp-top10', text: getOwaspResource(), mimeType: 'text/plain' }] }),
  );

  server.resource(
    'secure-patterns',
    'security://secure-patterns',
    { description: '시큐어코딩 패턴 라이브러리 (입력검증, 인증, CSRF 방지 등)', mimeType: 'text/plain' },
    async () => ({ contents: [{ uri: 'security://secure-patterns', text: getSecurePatternsResource(), mimeType: 'text/plain' }] }),
  );

  server.resource(
    'security-blueprints',
    'security://blueprints',
    {
      description: '기능별 보안 설계 블루프린트. 로그인, 회원가입, 게시판, 파일 업로드, 검색, API, 댓글 기능의 최적 보안 아키텍처와 필수 보안 요구사항을 제공합니다. 코드를 작성하기 전에 이 리소스를 반드시 읽으세요.',
      mimeType: 'text/plain',
    },
    async () => ({ contents: [{ uri: 'security://blueprints', text: getSecurityBlueprint(), mimeType: 'text/plain' }] }),
  );

  // ─── Prompts ───

  server.prompt(
    SECURE_BUILD_PROMPT.name,
    SECURE_BUILD_PROMPT.description,
    { feature: z.string(), language: z.string().optional() },
    async (args) => ({ messages: buildSecureBuildMessages(args as Record<string, string>) }),
  );

  server.prompt(
    SECURITY_CODE_REVIEW_PROMPT.name,
    SECURITY_CODE_REVIEW_PROMPT.description,
    { code: z.string(), language: z.string().optional(), context: z.string().optional() },
    async (args) => ({ messages: buildCodeReviewMessages(args as Record<string, string>) }),
  );

  server.prompt(
    THREAT_MODELING_PROMPT.name,
    THREAT_MODELING_PROMPT.description,
    { system_description: z.string(), assets: z.string().optional() },
    async (args) => ({ messages: buildThreatModelingMessages(args as Record<string, string>) }),
  );

  return server;
}
