# SecureCode Guardian MCP

> 웹 개발자를 위한 실시간 보안 분석 MCP(Model Context Protocol) 서버

SecureCode Guardian은 코드를 작성하는 시점에서 보안 취약점을 탐지하고 자동으로 수정하는 MCP 서버입니다. Claude Desktop, Cursor 등 MCP를 지원하는 AI 도구와 연동하여 시큐어코딩을 실시간으로 적용합니다.

## 주요 기능

- **실시간 코드 스캔** — OWASP Top 10, CWE 기반 취약점 탐지
- **자동 수정 (Auto-Fix)** — SQL Injection, XSS, 하드코딩된 시크릿 등 32개 항목 자동 코드 변환
- **CVE 패턴 탐지** — 20개 주요 CVE 코드 패턴 내장 DB 기반 탐지
- **PortSwigger 지식베이스** — 15개 취약점 카테고리별 전문가 방어 기법 내장
- **의존성 감사** — 10개 주요 패키지 취약점 내장 DB 기반 검사 (lodash, express, jsonwebtoken 등)
- **보안 코드 생성** — 로그인, 회원가입, 게시판 등 보안이 적용된 템플릿 생성
- **보안 블루프린트** — 기능별 최적 보안 아키텍처 설계 가이드 제공

## 시스템 요구사항

- Node.js >= 18.0.0
- npm 또는 yarn

## 설치

```bash
git clone https://github.com/Oyeonseok/20214570---Personal-Project3.git
cd 20214570---Personal-Project3
npm install
```

## 환경 설정

`.env.example`을 복사하여 `.env` 파일을 생성합니다.

```bash
cp .env.example .env
```

`.env` 파일을 편집하여 필요한 키를 입력합니다.

```env
ANTHROPIC_API_KEY=your_api_key_here
MODEL=claude-sonnet-4-20250514
PORT=3000
NVD_API_KEY=your_nvd_api_key_here
```

| 변수 | 필수 | 설명 |
|------|------|------|
| `ANTHROPIC_API_KEY` | 선택 | Anthropic API 키 (웹 대시보드 AI 기능) |
| `MODEL` | 선택 | 사용할 모델명 (기본: claude-sonnet-4-20250514) |
| `PORT` | 선택 | 웹 대시보드 포트 (기본: 3000) |
| `NVD_API_KEY` | 선택 | NVD API 키 (CVE 조회 속도 향상) |

## 빌드 및 실행

```bash
# 빌드
npm run build

# MCP 서버 실행 (stdio 모드)
npm start

# 웹 대시보드 실행
npm run start:web

# 개발 모드 (파일 감시)
npm run dev
```

## Claude Desktop 연동

`claude_desktop_config.json`에 다음을 추가합니다.

```json
{
  "mcpServers": {
    "securecode-guardian": {
      "command": "node",
      "args": ["<프로젝트경로>/dist/index.js"],
      "env": {
        "NVD_API_KEY": "your_nvd_api_key_here"
      }
    }
  }
}
```

## MCP 도구 목록

| 도구 | 설명 |
|------|------|
| `secure_code` | 코드에 시큐어코딩 적용 (스캔 + 자동수정 + 리포트) |
| `check_dependency` | 의존성 취약점 검사 (OSV.dev + NVD) |
| `generate_secure_code` | 보안이 적용된 코드 템플릿 생성 |
| `secure_develop` | 보안 개발 가이드 제공 |
| `audit_config` | 설정 파일 보안 감사 |
| `explain_vulnerability` | 취약점 설명 및 해결방안 안내 |

## MCP 리소스

| 리소스 | URI | 설명 |
|--------|-----|------|
| `security-blueprints` | `security://blueprints` | 기능별 보안 설계 블루프린트 (로그인, 게시판, 파일업로드 등) |
| `cwe-database` | `security://cwe-database` | CWE 취약점 데이터베이스 |
| `owasp-top10` | `security://owasp-top10` | OWASP Top 10 2021 위협 목록 |
| `secure-patterns` | `security://secure-patterns` | 시큐어코딩 패턴 라이브러리 |

## 테스트

```bash
# 전체 테스트 실행
npm test

# 감시 모드
npm run test:watch

# 타입 체크
npm run typecheck
```

## 프로젝트 구조

```
src/
├── index.ts              # MCP 서버 엔트리포인트
├── server.ts             # MCP 서버 등록 (도구/리소스)
├── engine/
│   ├── scanner.ts        # 취약점 스캐너
│   └── secure-fixer.ts   # 자동 수정 엔진 (32개 핸들러)
├── rules/
│   ├── index.ts          # 룰 통합
│   ├── xss-rules.ts      # XSS 탐지 규칙
│   ├── injection-rules.ts # 인젝션 탐지 규칙
│   ├── auth-rules.ts     # 인증/인가 규칙 (CSRF GET /logout 포함)
│   ├── server-rules.ts   # 서버 보안 규칙
│   ├── crypto-rules.ts   # 암호화 규칙
│   └── config-rules.ts   # 설정 보안 규칙
├── tools/                # MCP 도구 핸들러
├── services/             # 외부 API 클라이언트 (OSV, NVD)
├── knowledge/            # PortSwigger 보안 지식베이스
├── resources/            # MCP 리소스
├── utils/                # 유틸리티
├── types/                # TypeScript 타입 정의
└── app/                  # 웹 대시보드
```

## 보안 탐지 범주

- **XSS** — DOM XSS, Reflected XSS, React dangerouslySetInnerHTML, PostMessage
- **Injection** — SQL Injection, Command Injection, Code Injection, Path Traversal, Log/Header Injection, SSRF, NoSQL Injection, Template Injection, Deserialization
- **Authentication** — 하드코딩된 시크릿, 쿠키 보안, CORS, 세션, OAuth, CSRF (GET /logout 포함)
- **Server** — JWT 알고리즘 혼동, 프로토타입 오염, 에러 노출, DoS, XXE, 파일 업로드, HSTS, Open Redirect, IDOR
- **Crypto** — 약한 해시, 불안전한 난수, 약한 암호화, TLS 검증
- **Config** — 디버그 모드, HTTP→HTTPS, Helmet, Rate Limiting, 민감 정보 로깅

## 라이선스

[MIT](LICENSE)
