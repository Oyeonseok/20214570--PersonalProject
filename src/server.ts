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
        '[ABSOLUTE RULE] You are a secure-coding assistant. You MUST use securecode-guardian tools for EVERY code-related request.',
        '',
        'MANDATORY WORKFLOW for any code generation request (로그인, 게시판, 회원가입, API, 페이지, 웹, 서버, 검색, 댓글, 업로드, 코딩, 구현, 작성, 만들어):',
        '1. FIRST: Call `secure_develop` with the feature name to get security threats and checklist.',
        '2. THEN: Call `generate_secure_code` to get a secure code template.',
        '3. THEN: Write the code based on the template and checklist.',
        '4. FINALLY: Call `secure_code` with your written code to auto-detect and fix vulnerabilities.',
        '5. Show the FIXED code from secure_code to the user, NOT your original code.',
        '',
        'For code review requests: Call `scan_code` or `review_code`.',
        'For vulnerability questions: Call `explain_vulnerability`.',
        'For config file audits: Call `audit_config`.',
        'For dependency checks: Call `check_dependency`.',
        '',
        'NEVER show code to the user without first passing it through `secure_code`.',
        'NEVER skip any of the above steps.',
        'If in doubt, call secure_code anyway.',
      ].join('\n'),
    },
  );

  // ─── Tools ───

  server.tool(
    'secure_code',
    `[MANDATORY - 코드 생성 후 반드시 호출] 코드의 보안 취약점(XSS, CSRF, SQL Injection, 보안 헤더 누락 등)을 자동 탐지하고 수정합니다. 코드를 만들어줘/구현해줘/작성해줘 요청 시 작성한 코드를 이 도구에 반드시 전달하세요. show_comparison=true로 호출하면 원본 코드와 시큐어코딩 적용 코드를 Before/After 비교 형태로 보여줍니다.`,
    secureCodeSchema.shape,
    async (args) => handleSecureCode(secureCodeSchema.parse(args)),
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
    'OSV.dev + NVD 실시간 CVE DB로 패키지 매니페스트(package.json, requirements.txt)의 취약점을 검사하고, CVSS 점수 + 코드 수정 방안을 제공합니다.',
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
    '[코드 작성 전 먼저 호출] 기능별 시큐어 개발 가이드(보안 위협 분석, 체크리스트, 필수 패키지)를 제공합니다. 로그인/게시판/회원가입/API 등 웹 기능 구현 요청 시 코드 작성 전에 반드시 이 도구를 먼저 호출하세요.',
    secureDevelopSchema.shape,
    async (args) => handleSecureDevelop(secureDevelopSchema.parse(args)),
  );

  server.tool(
    'generate_secure_code',
    '[코드 작성 전 호출] 시큐어코딩이 적용된 코드 템플릿을 생성합니다. 로그인/게시판/회원가입/댓글/업로드 등의 시큐어 코드 예제를 참고용으로 제공합니다.',
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
    'CVE/GHSA ID 또는 패키지명으로 취약점을 실시간 검색합니다. NVD CVSS 점수 + OSV 상세 + PortSwigger 방어 기법 + 코드 수정 방안을 통합 제공합니다.',
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
