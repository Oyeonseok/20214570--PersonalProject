# 시큐어코딩 MCP (SecureCode Guardian) - 소프트웨어 요구사항명세서 (SRS)

**문서 버전**: v1.1.0  
**작성일**: 2026-02-26  
**문서 분류**: 기밀 / 내부용  
**프로젝트명**: SecureCode Guardian MCP  
**핵심 키워드**: MCP + LLM 하이브리드 보안 분석  

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [비즈니스 요구사항](#2-비즈니스-요구사항)
3. [LLM 연동 아키텍처](#3-llm-연동-아키텍처) ← **v1.1 신규**
4. [시스템 아키텍처](#4-시스템-아키텍처)
5. [기능 요구사항](#5-기능-요구사항)
6. [비기능 요구사항](#6-비기능-요구사항)
7. [MCP 도구(Tool) 상세 명세](#7-mcp-도구tool-상세-명세)
8. [MCP 리소스(Resource) 상세 명세](#8-mcp-리소스resource-상세-명세)
9. [MCP 프롬프트(Prompt) 상세 명세](#9-mcp-프롬프트prompt-상세-명세)
10. [보안 탐지 룰 체계](#10-보안-탐지-룰-체계)
11. [데이터 모델](#11-데이터-모델)
12. [외부 인터페이스](#12-외부-인터페이스)
13. [LLM 연동 상세 설계](#13-llm-연동-상세-설계) ← **v1.1 신규**
14. [제약사항 및 전제조건](#14-제약사항-및-전제조건)
15. [릴리스 계획](#15-릴리스-계획)
16. [용어 정의](#16-용어-정의)

---

## 1. 프로젝트 개요

### 1.1 프로젝트 배경

웹 애플리케이션 보안 사고의 약 70%는 개발 단계에서 예방 가능한 취약점에서 기인한다. 
그러나 대부분의 웹 개발자는 보안 전문가가 아니며, OWASP Top 10 수준의 기본적인 보안 위협조차 
코드 작성 시점에서 인지하지 못하는 경우가 빈번하다.

기존의 정적 분석 도구(SAST)는 빌드 후 또는 CI/CD 파이프라인에서 동작하여, 
개발자가 코드를 작성하는 **바로 그 시점**에 보안 피드백을 제공하지 못한다.

본 프로젝트는 **MCP(Model Context Protocol)** 기반으로, AI 코딩 어시스턴트가 
코드를 분석하고 작성하는 시점에 **실시간 보안 분석, 취약점 탐지, 시큐어코딩 가이드**를 
제공하는 도구를 개발한다.

### 1.2 프로젝트 비전

> "모든 웹 개발자의 코드에 20년차 보안 전문가의 눈을 심는다."

개발자가 별도의 보안 도구를 학습하거나 워크플로를 변경하지 않고도, 
AI 어시스턴트를 통해 자연스럽게 시큐어코딩을 실천할 수 있는 환경을 만든다.

### 1.3 대상 사용자

| 사용자 유형 | 설명 | 주요 니즈 |
|---|---|---|
| **주니어 웹 개발자** | 보안 지식이 부족한 1~3년차 | 무엇이 위험한지 알려주고, 안전한 코드를 제시 |
| **시니어 웹 개발자** | 보안 인식은 있으나 최신 위협 대응 부족 | 최신 CVE/공격기법 기반 정밀 분석 |
| **풀스택 개발자** | 프론트+백엔드 동시 개발 | 전 레이어에 걸친 통합 보안 검증 |
| **DevSecOps 엔지니어** | CI/CD에 보안 게이트 통합 | 자동화된 보안 리포트 및 정책 적용 |
| **프리랜서/스타트업** | 보안 전담 인력 부재 | 비용 효율적 보안 코드 리뷰 대체 |

### 1.4 지원 기술 스택

| 카테고리 | 지원 대상 (Phase 1) | 확장 예정 (Phase 2+) |
|---|---|---|
| **언어** | JavaScript, TypeScript, Python, Java | Go, Rust, PHP, C# |
| **프레임워크** | React, Next.js, Express, FastAPI, Spring Boot | Django, NestJS, Laravel |
| **DB** | MySQL, PostgreSQL, MongoDB | Redis, DynamoDB |
| **인프라** | Docker, AWS 기본 | K8s, Terraform |

---

## 2. 비즈니스 요구사항

### 2.1 비즈니스 목표

| ID | 목표 | 측정 지표(KPI) | 목표치 |
|---|---|---|---|
| BG-01 | 개발 단계 취약점 사전 차단 | 프로덕션 배포 전 취약점 탐지율 | ≥ 85% |
| BG-02 | 개발자 보안 역량 향상 | 동일 취약점 반복 발생률 감소 | 월 20% 감소 |
| BG-03 | 보안 코드리뷰 비용 절감 | 수동 보안 리뷰 시간 절감 | ≥ 60% 절감 |
| BG-04 | 컴플라이언스 준수 자동화 | OWASP/CWE 매핑 자동 보고서 | 100% 자동화 |
| BG-05 | 시큐어코딩 표준 일관성 | 팀 내 보안 코딩 표준 준수율 | ≥ 90% |

### 2.2 수익 모델

| 티어 | 대상 | 가격 | 주요 기능 |
|---|---|---|---|
| **Free** | 개인 개발자 | 무료 | 기본 취약점 스캔 (일 50회), OWASP Top 10 |
| **Pro** | 전문 개발자 | $19/월 | 무제한 스캔, 고급 룰셋, 커스텀 룰 |
| **Team** | 소규모 팀 | $49/월/5인 | Pro + 팀 정책, 대시보드, 리포트 |
| **Enterprise** | 기업 | 협의 | Team + 온프레미스, 커스텀 통합, SLA |

### 2.3 경쟁 분석

| 항목 | Snyk Code | SonarQube | GitHub CodeQL | **SecureCode Guardian** |
|---|---|---|---|---|
| 실시간 IDE 피드백 | △ | × | × | **◎** |
| AI 기반 수정 제안 | × | × | × | **◎** |
| MCP 네이티브 | × | × | × | **◎** |
| 자연어 보안 설명 | × | × | × | **◎** |
| 학습 기능 | × | △ | × | **◎** |
| 비용 (개인) | 무료/유료 | 무료/유료 | 무료 | **무료/유료** |

---

## 3. LLM 연동 아키텍처

> **v1.1 신규 섹션** - LLM과의 통합 구조를 정의한다.

### 3.1 LLM 연동 전략 개요

본 MCP는 LLM과 **양방향**으로 연동된다.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     LLM 연동 양방향 구조                              │
│                                                                      │
│   ① LLM → MCP (LLM이 도구를 호출)                                   │
│   ──────────────────────────────                                     │
│   LLM이 사용자 코드를 분석할 때 MCP Tools를 호출하여                  │
│   룰 기반 정적 분석 결과를 받아온다.                                   │
│   = LLM의 "손과 눈" 역할                                             │
│                                                                      │
│   ② MCP → LLM (MCP가 LLM을 활용)                                    │
│   ──────────────────────────────                                     │
│   룰 기반으로 탐지 불가능한 비즈니스 로직 취약점,                       │
│   컨텍스트 의존 취약점을 LLM의 추론 능력으로 분석한다.                  │
│   = MCP의 "두뇌" 역할                                                │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 양방향 데이터 흐름

```
사용자 (개발자)
    │
    │ "이 코드 보안 검토해줘"
    ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Host LLM (Claude / GPT / etc.)                 │
│                                                                    │
│  1. 사용자 요청 해석                                                │
│  2. 코드 컨텍스트 파악 (언어, 프레임워크, 용도)                      │
│  3. 적절한 MCP Tool 선택 및 호출                                    │
│  4. MCP 결과를 해석하고 사용자에게 자연어로 전달                      │
│  5. 추가 분석 필요 시 다른 Tool 체이닝                               │
│                                                                    │
│  [Tool Call 판단 로직]                                              │
│  ┌────────────────────────────────────────────────────────┐       │
│  │ IF 코드 스니펫 분석 → scan_code                         │       │
│  │ IF 파일 분석 → scan_file                                │       │
│  │ IF 의존성 검사 → check_dependency                       │       │
│  │ IF 안전한 코드 요청 → generate_secure_code              │       │
│  │ IF 취약점 설명 요청 → explain_vulnerability             │       │
│  │ IF 설정 검토 → audit_config                             │       │
│  │ IF 여러 도구 필요 → 순차/병렬 체이닝                     │       │
│  └────────────────────────────────────────────────────────┘       │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                         │ MCP Protocol (Tool Call)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                SecureCode Guardian MCP Server                      │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   분석 파이프라인                              │ │
│  │                                                               │ │
│  │  Stage 1: 룰 기반 정적 분석 (빠름, 확정적)                    │ │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐   │ │
│  │  │ AST     │→│ Pattern  │→│ Taint    │→│ Rule          │   │ │
│  │  │ Parsing │ │ Matching │ │ Tracking │ │ Evaluation    │   │ │
│  │  └─────────┘ └──────────┘ └──────────┘ └───────┬───────┘   │ │
│  │                                                  │           │ │
│  │  Stage 2: LLM 보강 분석 (깊음, 추론적) ← 선택적  │           │ │
│  │  ┌──────────────────────────────────────┐       │           │ │
│  │  │ 내장 LLM 분석 모듈                    │       │           │ │
│  │  │                                      │       │           │ │
│  │  │ • 비즈니스 로직 취약점 추론            │◄──────┘           │ │
│  │  │ • 컨텍스트 기반 오탐 필터링            │                   │ │
│  │  │ • 자연어 취약점 설명 생성              │                   │ │
│  │  │ • 공격 시나리오 구체화                 │                   │ │
│  │  │ • 맞춤형 수정 코드 생성                │                   │ │
│  │  └──────────────┬───────────────────────┘                   │ │
│  │                  │                                            │ │
│  │  Stage 3: 결과 통합 및 응답 구성                              │ │
│  │  ┌──────────────▼───────────────────────────────────────┐   │ │
│  │  │ Result Aggregator                                     │   │ │
│  │  │ • 룰 분석 + LLM 분석 결과 병합                         │   │ │
│  │  │ • 중복 제거 및 심각도 재산정                            │   │ │
│  │  │ • 신뢰도 점수 산출                                     │   │ │
│  │  │ • LLM-friendly 출력 포맷팅                             │   │ │
│  │  └──────────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                         │
                         │ 구조화된 분석 결과 (JSON)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Host LLM (결과 해석)                            │
│                                                                    │
│  MCP 결과를 받아서:                                                │
│  • 개발자 수준에 맞는 자연어 설명으로 변환                           │
│  • 코드 수정 제안을 IDE에 직접 적용 가능한 형태로 제시                │
│  • 추가 질문이나 심화 분석 유도                                     │
│  • 교육적 컨텍스트 제공 (왜 위험한지, 실제 사고 사례 등)             │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 LLM 활용 모드 (3-Tier Analysis)

본 MCP는 3단계 분석 모드를 지원하여, 비용과 분석 깊이를 사용자가 선택할 수 있다.

| 모드 | 분석 방식 | LLM 사용 | 응답 속도 | 분석 깊이 | 비용 |
|---|---|---|---|---|---|
| **Lite** | 룰 기반만 | 없음 | ≤ 500ms | 패턴 매칭 수준 | 무료 |
| **Standard** | 룰 + Host LLM 해석 | Host LLM만 | ≤ 2초 | 컨텍스트 이해 | 무료 |
| **Deep** | 룰 + 내장 LLM 추론 | 내장 LLM 호출 | ≤ 10초 | 비즈니스 로직 수준 | 유료 |

```
[Lite Mode - 무료, 빠름]
코드 → AST/Pattern/Taint → 룰 매칭 → 결과 JSON
       (MCP 내부만 사용)

[Standard Mode - 무료, 기본]  
코드 → AST/Pattern/Taint → 룰 매칭 → 결과 JSON → Host LLM이 해석/보강
       (MCP 분석 + Host LLM 추론)

[Deep Mode - 유료, 정밀]
코드 → AST/Pattern/Taint → 룰 매칭 ─┐
                                      ├→ 통합 결과 → Host LLM이 해석
코드 → 내장 LLM 시맨틱 분석 ──────────┘
       (MCP 분석 + 내장 LLM 분석 + Host LLM 해석)
```

### 3.4 "MCP → LLM" 내장 LLM 분석 모듈 상세

룰 기반 분석으로는 탐지할 수 없는 영역을 LLM이 보완한다.

#### 3.4.1 내장 LLM이 담당하는 분석 영역

| 분석 영역 | 룰 기반 한계 | LLM 보강 효과 |
|---|---|---|
| **비즈니스 로직 취약점** | 패턴 없음, 탐지 불가 | 코드의 의도를 파악하여 논리 오류 발견 |
| **Race Condition** | 단순 패턴 매칭 한계 | 동시성 시나리오 추론 |
| **권한 상승 경로** | 단일 파일 분석 한계 | 다중 파일 간 호출 흐름 추론 |
| **오탐 필터링** | 높은 오탐률 | 코드 의도 이해로 오탐 70% 감소 |
| **수정 코드 생성** | 템플릿 기반 제한적 | 프로젝트 스타일에 맞는 맞춤 코드 |
| **공격 시나리오** | 정형화된 설명 | 해당 코드에 특화된 구체적 시나리오 |
| **자연어 설명** | 고정 메시지 | 개발자 수준에 맞는 맞춤 설명 |

#### 3.4.2 내장 LLM Provider 지원

```typescript
interface LLMProviderConfig {
  provider: 'openai' | 'anthropic' | 'ollama' | 'custom';
  model: string;
  apiKey?: string;        // 외부 API 시 (환경변수 참조)
  baseUrl?: string;       // Ollama, custom 엔드포인트
  maxTokens: number;
  temperature: number;    // 보안 분석은 낮은 temperature 권장 (0.1~0.3)
  timeout: number;        // ms
}
```

| Provider | 모델 예시 | 특징 | 비용 |
|---|---|---|---|
| **Anthropic** | Claude 3.5 Sonnet | 코드 이해력 우수, 안전성 높음 | API 과금 |
| **OpenAI** | GPT-4o | 범용성 높음 | API 과금 |
| **Ollama** | CodeLlama, DeepSeek-Coder | 로컬 실행, 무료, 프라이버시 | GPU 필요 |
| **Custom** | 자체 모델/엔드포인트 | 기업 커스터마이징 | 자체 인프라 |

#### 3.4.3 내장 LLM 호출 시 보안 원칙

```
┌─────────────────────────────────────────────────────────────┐
│              LLM 호출 시 보안 정책 (철칙)                     │
│                                                               │
│  1. 코드 전송 최소화                                          │
│     - 전체 파일이 아닌 취약점 주변 컨텍스트만 전송              │
│     - 민감정보(시크릿, API 키) 자동 마스킹 후 전송             │
│                                                               │
│  2. 프라이버시 모드 지원                                      │
│     - "local-only" 설정 시 Ollama만 사용 (외부 전송 없음)     │
│     - 기업 환경: 자체 LLM 엔드포인트 사용 필수                │
│                                                               │
│  3. LLM 응답 검증                                             │
│     - LLM이 생성한 수정 코드도 룰 기반으로 재검증              │
│     - 환각(Hallucination) 방지: CWE/CVE ID 존재 여부 확인     │
│                                                               │
│  4. 비용 제어                                                 │
│     - 일일/월간 LLM 호출 한도 설정                             │
│     - 토큰 사용량 추적 및 리포트                               │
│     - 캐시: 동일 코드 패턴은 LLM 재호출하지 않음              │
│                                                               │
│  5. Fallback                                                  │
│     - LLM 응답 실패/타임아웃 시 룰 기반 결과만 반환           │
│     - LLM 미설정 시 Lite 모드로 자동 전환                     │
└─────────────────────────────────────────────────────────────┘
```

### 3.5 Host LLM을 위한 Tool 설계 원칙

MCP Tools는 궁극적으로 **Host LLM이 호출**한다. LLM이 올바른 도구를 올바른 타이밍에 호출하도록 설계해야 한다.

#### 3.5.1 Tool Description 최적화 (LLM이 읽는 설명)

```typescript
// ❌ BAD: LLM이 언제 호출해야 할지 모호
{
  name: "scan_code",
  description: "코드를 스캔합니다"
}

// ✅ GOOD: LLM이 정확히 판단할 수 있는 설명
{
  name: "scan_code",
  description: `웹 보안 취약점(SQL Injection, XSS, CSRF, 인증우회 등)을 
  코드 스니펫에서 탐지합니다. 사용자가 코드를 보여주며 "보안 검토", 
  "취약점 확인", "안전한지 확인" 등을 요청할 때 호출하세요.
  결과에는 취약점 위치, 심각도, 공격 시나리오, 수정 코드가 포함됩니다.
  scan_file과 다르게 파일 경로가 아닌 코드 문자열을 직접 받습니다.`
}
```

#### 3.5.2 LLM Tool 호출 체이닝 시나리오

Host LLM이 여러 MCP Tool을 조합하여 사용하는 대표 시나리오:

**시나리오 A: 종합 보안 리뷰**
```
사용자: "이 Express 서버 코드 전체 보안 검토해줘"

LLM 판단 → Tool 체이닝:
  1. scan_code(코드, context="backend", framework="express")
     → 코드 레벨 취약점 탐지
  2. check_dependency(package.json 경로)
     → 의존성 CVE 검사
  3. audit_config(.env 경로)
     → 설정 파일 보안 검사
  4. explain_vulnerability(발견된 Critical 취약점)
     → 심각한 취약점 상세 설명
  5. generate_secure_code(취약 코드, framework="express")
     → 수정 코드 생성

LLM → 사용자: 종합 리포트 + 수정 코드 + 교육적 설명
```

**시나리오 B: 실시간 코딩 중 보안 가드**
```
사용자: "로그인 API 만들어줘"

LLM 판단 → Resource 참조 + Tool 사용:
  1. [Resource] secureguard://patterns/typescript/authentication
     → 안전한 인증 패턴 참조
  2. generate_secure_code(task="JWT 로그인 API", framework="express")
     → 시큐어 코드 생성
  3. scan_code(생성된 코드)
     → 생성된 코드 자체 검증

LLM → 사용자: 보안이 적용된 로그인 API 코드 제공
```

**시나리오 C: 학습 모드**
```
사용자: "SQL Injection이 뭐야? 내 코드에서 예시 보여줘"

LLM 판단:
  1. [Resource] secureguard://cwe/89
     → SQL Injection CWE 정보 참조
  2. [Resource] secureguard://owasp/top10/2021 (A03)
     → OWASP 가이드 참조
  3. scan_code(사용자 코드)
     → 실제 취약점 위치 탐지
  4. explain_vulnerability(결과, detail_level="beginner", include_demo=true)
     → 초급자용 상세 설명 + 공격 데모

LLM → 사용자: 사용자 코드 기반 SQLi 교육 컨텐츠
```

**시나리오 D: DevSecOps 파이프라인**
```
사용자: "프로젝트 전체 스캔하고 SARIF 리포트 만들어줘"

LLM 판단:
  1. scan_project(프로젝트 경로)
     → 전체 프로젝트 스캔
  2. check_dependency(package.json)
     → 의존성 검사
  3. generate_report(format="sarif", scan_results)
     → SARIF 리포트 생성

LLM → 사용자: 리포트 파일 경로 + 핵심 요약
```

### 3.6 LLM 연동 설정 (사용자 구성)

사용자는 MCP 서버 설정에서 LLM 연동을 구성한다.

```jsonc
// MCP 서버 설정 파일: secureguard.config.json
{
  "analysis": {
    // 분석 모드: "lite" | "standard" | "deep"
    "mode": "standard",
    
    // 오탐 필터링에 LLM 사용 여부
    "llm_false_positive_filter": true,
    
    // 수정 코드 생성에 LLM 사용 여부
    "llm_remediation": true
  },
  
  "llm": {
    // Deep 모드에서 사용할 내장 LLM 설정
    "provider": "ollama",           // 로컬 우선
    "model": "deepseek-coder-v2",
    "base_url": "http://localhost:11434",
    
    // 또는 외부 API
    // "provider": "anthropic",
    // "model": "claude-3-5-sonnet-20241022",
    // "api_key_env": "ANTHROPIC_API_KEY",  // 환경변수 참조
    
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout_ms": 15000,
    
    // 비용 제어
    "daily_token_limit": 100000,
    "cache_ttl_minutes": 60
  },
  
  "privacy": {
    // true면 외부 API 호출 전면 차단 (Ollama만 허용)
    "local_only": false,
    
    // LLM 전송 전 자동 마스킹 패턴
    "mask_patterns": [
      "(?i)(api[_-]?key|secret|password|token)\\s*[:=]\\s*['\"][^'\"]+['\"]",
      "(?i)(aws_access_key|aws_secret)\\s*[:=]\\s*['\"][^'\"]+['\"]"
    ],
    
    // LLM에 전송할 코드 주변 컨텍스트 라인 수
    "context_window_lines": 20
  }
}
```

### 3.7 LLM 프롬프트 엔지니어링 전략

#### 3.7.1 내장 LLM 분석 시스템 프롬프트

MCP 내부에서 LLM을 호출할 때 사용하는 시스템 프롬프트:

```
당신은 20년 경력의 웹 보안 전문가이며 공격자의 관점에서 사고합니다.

[분석 원칙]
1. 모든 외부 입력(HTTP 파라미터, 헤더, 쿠키, 파일, DB)을 "오염된(tainted)" 데이터로 취급
2. 인증과 인가를 별개의 문제로 분석
3. 클라이언트 측 검증은 보안 수단이 아님을 전제
4. 프레임워크의 기본 보안 기능이 올바르게 활용되었는지 확인
5. 에러 핸들링이 정보를 노출하는지 확인

[출력 형식]
반드시 아래 JSON 형식으로만 응답:
{
  "findings": [...],
  "false_positive_candidates": [...],
  "business_logic_concerns": [...],
  "overall_risk_assessment": "..."
}

[금지 사항]
- 존재하지 않는 CWE/CVE ID를 생성하지 마세요
- 확실하지 않은 취약점은 confidence를 "low"로 표기
- 코드의 의도를 과도하게 추측하지 마세요
```

#### 3.7.2 Host LLM용 MCP Prompt 템플릿 최적화

MCP Prompts는 Host LLM이 보안 전문가처럼 동작하게 만드는 프리셋이다.

```typescript
// MCP Prompt: security_code_review
{
  name: "security_code_review",
  description: "코드의 보안 취약점을 전문가 수준으로 리뷰합니다. 사용자가 보안 리뷰를 요청하면 이 프롬프트를 사용하세요.",
  arguments: [
    { name: "code", description: "리뷰할 코드", required: true },
    { name: "language", description: "프로그래밍 언어", required: false },
    { name: "context", description: "코드 용도 (API, 인증, 결제 등)", required: false },
    { name: "developer_level", description: "개발자 수준 (junior/senior)", required: false }
  ],
  // Host LLM에 주입되는 메시지
  messages: [
    {
      role: "system",
      content: `당신은 웹 보안 20년차 전문가입니다.
      
      [분석 절차]
      1. scan_code 도구로 자동 취약점 탐지 실행
      2. 결과를 분석하고 오탐 여부 판단
      3. 자동 탐지로 놓친 비즈니스 로직 취약점 추가 분석
      4. 심각도 순으로 정리하여 설명
      5. 각 취약점의 수정 코드 제시
      6. 전반적인 보안 수준 평가
      
      [응답 스타일]
      - ${developer_level}에 맞는 설명 수준
      - 실제 공격 시나리오로 위험성 체감시키기
      - 수정 코드는 복사-붙여넣기로 바로 적용 가능하게`
    },
    {
      role: "user", 
      content: "다음 ${language} 코드를 보안 검토해주세요.\n\n컨텍스트: ${context}\n\n```\n${code}\n```"
    }
  ]
}
```

### 3.8 LLM 호환 IDE/클라이언트별 동작 방식

| 클라이언트 | MCP 지원 | LLM | 동작 방식 |
|---|---|---|---|
| **Cursor** | stdio | Claude | Agent가 Tool 자동 호출, 결과 인라인 표시 |
| **Claude Desktop** | stdio | Claude | Chat에서 Tool 호출, 대화형 분석 |
| **VS Code + Continue** | stdio | 선택가능 | Continue 확장이 MCP 중개 |
| **Zed** | stdio | Claude | 내장 AI가 MCP 호출 |
| **Custom Client** | SSE/HTTP | 선택가능 | 자체 LLM 파이프라인에서 호출 |

### 3.9 LLM 연동 시 핵심 고려사항

| 구분 | 고려사항 | 대응 전략 |
|---|---|---|
| **정확성** | LLM 환각(Hallucination)으로 잘못된 취약점 보고 | 룰 기반 결과 우선, LLM 결과는 보조 + 신뢰도 점수 표시 |
| **일관성** | 같은 코드를 넣어도 LLM 결과가 달라질 수 있음 | temperature 0.1, 결과 캐싱, 룰 기반 앵커링 |
| **비용** | Deep 모드 LLM 호출 비용 누적 | 토큰 한도, 캐시, Ollama 로컬 모드 권장 |
| **속도** | LLM 호출로 응답 지연 | Lite/Standard 모드 기본, Deep은 명시적 요청 시만 |
| **프라이버시** | 코드가 외부 LLM API로 전송 | local_only 모드, 민감정보 마스킹, 최소 컨텍스트 전송 |
| **가용성** | LLM API 다운 시 서비스 중단 | Lite 모드 자동 폴백, 오프라인에서도 핵심 기능 동작 |

---

## 4. 시스템 아키텍처

> 3장의 LLM 연동 아키텍처가 통합된 전체 시스템 구조

### 4.1 전체 아키텍처 개요 (LLM 통합 반영)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     IDE (Cursor / VS Code / Claude Desktop)          │
│  ┌─────────────┐    ┌──────────────────────────────────────────┐   │
│  │  Host LLM    │◄──►│        MCP Client (Built-in)             │   │
│  │  (Claude,    │    └──────────────┬───────────────────────────┘   │
│  │   GPT, etc.) │                   │                               │
│  │              │    ① LLM→MCP      │ MCP Protocol                  │
│  │  "보안 전문가  │    Tool Call      │ (stdio / SSE)                 │
│  │   페르소나"   │                   │                               │
│  └─────────────┘                    │                               │
└─────────────────────────────────────┼───────────────────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│               SecureCode Guardian MCP Server                         │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     MCP Transport Layer                         │  │
│  └──────────────┬────────────────────────────────────────────────┘  │
│                  │                                                    │
│  ┌───────────┐  │  ┌──────────────┐  ┌────────────────────┐        │
│  │   Tools    │  │  │  Resources   │  │     Prompts        │        │
│  │  Handler   │◄─┼─►│  Handler     │  │     Handler        │        │
│  └─────┬─────┘  │  └──────┬───────┘  └────────┬───────────┘        │
│        │        │         │                     │                    │
│  ┌─────▼────────▼─────────▼─────────────────────▼───────────────┐  │
│  │               Core Analysis Engine (하이브리드)                 │  │
│  │                                                                 │  │
│  │  [Stage 1: 룰 기반 분석 - 빠름, 확정적]                        │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────────────┐         │  │
│  │  │ AST        │ │ Pattern    │ │ Taint              │         │  │
│  │  │ Analyzer   │→│ Matcher    │→│ Tracker            │         │  │
│  │  └────────────┘ └────────────┘ └─────────┬──────────┘         │  │
│  │                                           │                     │  │
│  │  [Stage 2: LLM 보강 분석 - Deep 모드]     │                     │  │
│  │  ┌────────────────────────────────────┐   │                     │  │
│  │  │  ② MCP→LLM  LLM Analysis Module   │◄──┘                     │  │
│  │  │  ┌─────────────────────────────┐   │                         │  │
│  │  │  │ • 비즈니스 로직 취약점 추론   │   │  ┌──────────────────┐ │  │
│  │  │  │ • 오탐 필터링               │   │──►│ LLM Provider     │ │  │
│  │  │  │ • 맞춤 수정 코드 생성        │   │  │ (Ollama/OpenAI/  │ │  │
│  │  │  │ • 공격 시나리오 구체화       │   │  │  Anthropic)      │ │  │
│  │  │  └─────────────────────────────┘   │  └──────────────────┘ │  │
│  │  └────────────────────────────────────┘                         │  │
│  │                                                                 │  │
│  │  [Stage 3: 결과 통합]                                           │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Result Aggregator (룰 결과 + LLM 결과 병합/중복제거)     │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Rule Engine          │  Data Layer                            │  │
│  │  ┌─────────┐          │  ┌──────────┐ ┌────────────────────┐  │  │
│  │  │ OWASP   │          │  │ CVE DB   │ │ Knowledge Base     │  │  │
│  │  │ CWE     │          │  │ Rule DB  │ │ (패턴/공격벡터/    │  │  │
│  │  │ Custom   │          │  │ Cache DB │ │  조치가이드)       │  │  │
│  │  │ Framework│          │  └──────────┘ └────────────────────┘  │  │
│  │  └─────────┘          │                                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼ (Optional)
              ┌──────────────────────────────┐
              │  NVD API / OSV / GitHub      │
              │  Advisory Database           │
              └──────────────────────────────┘
```

### 4.2 기술 스택

| 레이어 | 기술 | 선정 이유 |
|---|---|---|
| **MCP Server** | TypeScript + Node.js | MCP SDK 공식 지원, 타입 안전성 |
| **분석 엔진** | TypeScript (AST 파싱) | tree-sitter, @babel/parser 활용 |
| **LLM 통합** | Vercel AI SDK (`ai`) | 멀티 프로바이더 지원, 스트리밍, 도구 호출 |
| **LLM 로컬** | Ollama | 프라이버시, 무료, 오프라인 분석 |
| **룰 엔진** | JSON Schema + YAML | 선언적 룰 정의, 확장 용이 |
| **로컬 DB** | SQLite (better-sqlite3) | 무설치, 빠른 로컬 조회 |
| **캐싱** | LRU Cache (in-memory) | 반복 스캔 + LLM 응답 캐싱 |
| **패키지 매니저** | pnpm | 디스크 효율성, 모노레포 지원 |
| **테스트** | Vitest | 빠른 실행, TypeScript 네이티브 |
| **빌드** | tsup | 빠른 번들링, ESM/CJS 동시 지원 |

### 4.3 디렉토리 구조

```
securecode-guardian-mcp/
├── src/
│   ├── index.ts                    # MCP 서버 엔트리포인트
│   ├── server.ts                   # MCP 서버 설정 및 핸들러 등록
│   ├── config.ts                   # 설정 로더 (LLM 설정 포함)
│   ├── tools/                      # MCP Tools 구현
│   │   ├── scan-code.ts            # 코드 취약점 스캔
│   │   ├── scan-file.ts            # 파일 단위 스캔
│   │   ├── scan-project.ts         # 프로젝트 전체 스캔
│   │   ├── check-dependency.ts     # 의존성 취약점 검사
│   │   ├── generate-secure.ts      # 시큐어 코드 생성
│   │   ├── explain-vuln.ts         # 취약점 상세 설명
│   │   ├── audit-config.ts         # 설정 파일 보안 감사
│   │   ├── check-headers.ts        # HTTP 보안 헤더 검사
│   │   └── report-generate.ts      # 보안 리포트 생성
│   ├── resources/                  # MCP Resources 구현
│   │   ├── owasp-top10.ts          # OWASP Top 10 가이드
│   │   ├── secure-patterns.ts      # 시큐어코딩 패턴 사전
│   │   ├── cwe-database.ts         # CWE 취약점 DB
│   │   └── cheatsheets.ts          # 보안 치트시트
│   ├── prompts/                    # MCP Prompts 구현
│   │   ├── code-review.ts          # 보안 코드리뷰 프롬프트
│   │   ├── threat-model.ts         # 위협 모델링 프롬프트
│   │   └── incident-response.ts    # 침해 대응 가이드 프롬프트
│   ├── engine/                     # 핵심 분석 엔진
│   │   ├── scanner/
│   │   │   ├── ast-analyzer.ts     # AST 기반 코드 분석
│   │   │   ├── pattern-matcher.ts  # 패턴 매칭 엔진
│   │   │   ├── taint-tracker.ts    # 오염 추적 분석
│   │   │   └── data-flow.ts        # 데이터 흐름 분석
│   │   ├── rules/
│   │   │   ├── rule-engine.ts      # 룰 실행 엔진
│   │   │   ├── rule-loader.ts      # 룰 로더
│   │   │   └── rule-validator.ts   # 룰 유효성 검증
│   │   ├── dependency/
│   │   │   ├── npm-checker.ts      # npm 의존성 검사
│   │   │   ├── pip-checker.ts      # pip 의존성 검사
│   │   │   └── osv-client.ts       # OSV API 클라이언트
│   │   ├── llm/                    # ★ LLM 통합 모듈
│   │   │   ├── llm-provider.ts     # LLM 프로바이더 추상화 (Ollama/OpenAI/Anthropic)
│   │   │   ├── llm-analyzer.ts     # LLM 기반 시맨틱 분석기
│   │   │   ├── prompt-builder.ts   # 보안 분석용 프롬프트 빌더
│   │   │   ├── response-parser.ts  # LLM 응답 구조화 파서
│   │   │   ├── hallucination-guard.ts  # 환각 방지 (CWE/CVE ID 검증)
│   │   │   ├── secret-masker.ts    # LLM 전송 전 민감정보 마스킹
│   │   │   └── token-tracker.ts    # 토큰 사용량 추적 및 비용 제어
│   │   └── reporter/
│   │       ├── json-reporter.ts    # JSON 리포트
│   │       ├── sarif-reporter.ts   # SARIF 형식 리포트
│   │       └── html-reporter.ts    # HTML 리포트
│   ├── aggregator/                 # ★ 결과 통합 모듈
│   │   ├── result-merger.ts        # 룰 결과 + LLM 결과 병합
│   │   ├── deduplicator.ts         # 중복 취약점 제거
│   │   └── confidence-scorer.ts    # 통합 신뢰도 산출
│   ├── rules/                      # 보안 룰 정의 (YAML/JSON)
│   │   ├── owasp/
│   │   │   ├── A01-broken-access-control.yaml
│   │   │   ├── A02-cryptographic-failures.yaml
│   │   │   ├── A03-injection.yaml
│   │   │   ├── A04-insecure-design.yaml
│   │   │   ├── A05-security-misconfiguration.yaml
│   │   │   ├── A06-vulnerable-components.yaml
│   │   │   ├── A07-auth-failures.yaml
│   │   │   ├── A08-data-integrity-failures.yaml
│   │   │   ├── A09-logging-monitoring-failures.yaml
│   │   │   └── A10-ssrf.yaml
│   │   ├── cwe/
│   │   │   ├── cwe-79-xss.yaml
│   │   │   ├── cwe-89-sqli.yaml
│   │   │   ├── cwe-352-csrf.yaml
│   │   │   ├── cwe-502-deserialization.yaml
│   │   │   └── ...
│   │   ├── framework/
│   │   │   ├── react-rules.yaml
│   │   │   ├── nextjs-rules.yaml
│   │   │   ├── express-rules.yaml
│   │   │   ├── fastapi-rules.yaml
│   │   │   └── spring-rules.yaml
│   │   └── custom/
│   │       └── .gitkeep
│   ├── knowledge/                  # 보안 지식 베이스
│   │   ├── secure-patterns/        # 시큐어코딩 패턴
│   │   ├── attack-vectors/         # 공격 벡터 DB
│   │   ├── system-prompts/         # ★ LLM 시스템 프롬프트 템플릿
│   │   │   ├── security-analyst.md # 보안 분석가 페르소나
│   │   │   ├── code-reviewer.md    # 코드 리뷰어 페르소나
│   │   │   └── attacker.md         # 공격자 관점 페르소나
│   │   └── remediation/            # 조치 가이드
│   ├── types/                      # TypeScript 타입 정의
│   │   ├── mcp.ts
│   │   ├── rules.ts
│   │   ├── scan-result.ts
│   │   ├── vulnerability.ts
│   │   └── llm.ts                  # ★ LLM 관련 타입 정의
│   └── utils/                      # 유틸리티
│       ├── logger.ts
│       ├── cache.ts
│       ├── language-detector.ts
│       └── severity-calculator.ts
├── tests/
│   ├── unit/
│   │   ├── engine/
│   │   └── llm/                    # ★ LLM 모듈 테스트
│   │       ├── hallucination-guard.test.ts
│   │       ├── secret-masker.test.ts
│   │       └── response-parser.test.ts
│   ├── integration/
│   │   └── llm-analysis.test.ts    # ★ LLM 통합 테스트
│   └── fixtures/                   # 취약한 코드 샘플 (테스트용)
│       ├── vulnerable/
│       └── secure/
├── docs/
│   └── SRS_SecureCoding_MCP.md     # 본 문서
├── secureguard.config.json         # ★ MCP + LLM 통합 설정
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── README.md
```

---

## 5. 기능 요구사항

### 4.1 MCP Tools (도구)

MCP Tools는 AI 에이전트가 호출하여 실행하는 **액션**이다.

| ID | Tool 명 | 설명 | 우선순위 |
|---|---|---|---|
| **FT-01** | `scan_code` | 코드 스니펫의 보안 취약점 실시간 분석 | P0 |
| **FT-02** | `scan_file` | 단일 파일의 보안 취약점 전체 스캔 | P0 |
| **FT-03** | `scan_project` | 프로젝트 전체 보안 스캔 (요약 포함) | P1 |
| **FT-04** | `check_dependency` | 의존성 패키지 알려진 취약점(CVE) 검사 | P0 |
| **FT-05** | `generate_secure_code` | 안전한 코드 패턴 생성/변환 | P0 |
| **FT-06** | `explain_vulnerability` | 발견된 취약점의 상세 설명 및 공격 시나리오 | P1 |
| **FT-07** | `audit_config` | 설정 파일(env, yaml, json) 보안 감사 | P1 |
| **FT-08** | `check_security_headers` | HTTP 보안 헤더 설정 검증 | P2 |
| **FT-09** | `generate_report` | 보안 분석 리포트 생성 (SARIF/JSON/HTML) | P2 |

### 4.2 MCP Resources (리소스)

MCP Resources는 AI 에이전트가 참조하는 **읽기 전용 데이터**이다.

| ID | Resource URI | 설명 | 우선순위 |
|---|---|---|---|
| **FR-01** | `secureguard://owasp/top10/{year}` | OWASP Top 10 가이드 | P0 |
| **FR-02** | `secureguard://cwe/{id}` | CWE 취약점 상세 정보 | P0 |
| **FR-03** | `secureguard://patterns/{language}/{category}` | 언어별 시큐어코딩 패턴 | P0 |
| **FR-04** | `secureguard://cheatsheet/{topic}` | 보안 치트시트 (인증, 암호화 등) | P1 |
| **FR-05** | `secureguard://cve/{id}` | CVE 상세 정보 | P1 |
| **FR-06** | `secureguard://compliance/{standard}` | 컴플라이언스 기준 (PCI-DSS, GDPR 등) | P2 |

### 4.3 MCP Prompts (프롬프트)

MCP Prompts는 특정 워크플로를 위한 **사전 정의된 프롬프트 템플릿**이다.

| ID | Prompt 명 | 설명 | 우선순위 |
|---|---|---|---|
| **FP-01** | `security_code_review` | 보안 관점 코드 리뷰 수행 | P0 |
| **FP-02** | `threat_modeling` | STRIDE 기반 위협 모델링 | P1 |
| **FP-03** | `incident_response_guide` | 취약점 발견 시 대응 가이드 | P2 |
| **FP-04** | `secure_architecture_review` | 아키텍처 보안 검토 | P2 |

---

## 6. 비기능 요구사항

### 5.1 성능 요구사항

| ID | 항목 | 요구사항 | 측정 방법 |
|---|---|---|---|
| NFR-P01 | 코드 스니펫 스캔 응답시간 | ≤ 500ms (100줄 이하) | 벤치마크 테스트 |
| NFR-P02 | 단일 파일 스캔 응답시간 | ≤ 3초 (1000줄 이하) | 벤치마크 테스트 |
| NFR-P03 | 프로젝트 스캔 응답시간 | ≤ 30초 (10,000줄 이하) | 벤치마크 테스트 |
| NFR-P04 | 메모리 사용량 | ≤ 256MB (유휴 시 ≤ 50MB) | 프로파일링 |
| NFR-P05 | CPU 사용률 | 스캔 중 ≤ 30% (단일 코어 기준) | 모니터링 |
| NFR-P06 | 캐시 적중률 | ≥ 70% (반복 스캔 시) | 캐시 메트릭 |

### 5.2 안정성 요구사항

| ID | 항목 | 요구사항 |
|---|---|---|
| NFR-R01 | 크래시 복구 | MCP 서버 비정상 종료 시 자동 재시작 (3회까지) |
| NFR-R02 | 에러 격리 | 단일 룰 실패가 전체 스캔을 중단시키지 않음 |
| NFR-R03 | 타임아웃 | 개별 룰 실행 10초, 전체 스캔 60초 타임아웃 |
| NFR-R04 | 정탐률 (Precision) | ≥ 80% (오탐률 ≤ 20%) |
| NFR-R05 | 재현율 (Recall) | ≥ 75% (OWASP Top 10 범위 내) |

### 5.3 보안 요구사항 (자체 보안)

| ID | 항목 | 요구사항 |
|---|---|---|
| NFR-S01 | 코드 비전송 | 사용자 코드가 외부 서버로 전송되지 않음 (로컬 분석) |
| NFR-S02 | 시크릿 비저장 | 분석 과정에서 발견된 시크릿을 로그/캐시에 저장하지 않음 |
| NFR-S03 | 룰 무결성 | 외부 룰 로드 시 서명 검증 (Phase 2) |
| NFR-S04 | 최소 권한 | 파일 시스템 읽기 전용 접근 (스캔 대상만) |
| NFR-S05 | 감사 로그 | 스캔 이력 로컬 저장 (민감정보 제외) |

### 5.4 호환성 요구사항

| ID | 항목 | 요구사항 |
|---|---|---|
| NFR-C01 | MCP 프로토콜 | MCP Specification 2025-03-26 이상 호환 |
| NFR-C02 | Node.js 버전 | Node.js 18 LTS 이상 |
| NFR-C03 | OS 지원 | Windows 10+, macOS 12+, Ubuntu 20.04+ |
| NFR-C04 | IDE 지원 | Cursor, VS Code (MCP 지원 에디터) |
| NFR-C05 | Transport | stdio (기본), SSE (원격), Streamable HTTP (원격) |

### 5.5 확장성 요구사항

| ID | 항목 | 요구사항 |
|---|---|---|
| NFR-E01 | 커스텀 룰 | 사용자 정의 YAML 룰 추가 지원 |
| NFR-E02 | 플러그인 | 서드파티 분석 엔진 플러그인 아키텍처 |
| NFR-E03 | 언어 확장 | 새 언어 지원을 위한 분석기 인터페이스 |
| NFR-E04 | 국제화 | 보안 설명 다국어 지원 (한/영/일) |

---

## 7. MCP 도구(Tool) 상세 명세

### 6.1 FT-01: `scan_code` - 코드 스니펫 취약점 스캔

**목적**: 주어진 코드 스니펫에서 보안 취약점을 실시간으로 탐지한다.

**입력 파라미터 (Input Schema)**:

```json
{
  "type": "object",
  "properties": {
    "code": {
      "type": "string",
      "description": "분석할 소스 코드 스니펫"
    },
    "language": {
      "type": "string",
      "enum": ["javascript", "typescript", "python", "java"],
      "description": "프로그래밍 언어 (미지정 시 자동 감지)"
    },
    "context": {
      "type": "string",
      "enum": ["frontend", "backend", "fullstack", "api", "config"],
      "description": "코드가 사용되는 컨텍스트"
    },
    "framework": {
      "type": "string",
      "description": "사용 중인 프레임워크 (예: express, react, nextjs)"
    },
    "severity_threshold": {
      "type": "string",
      "enum": ["critical", "high", "medium", "low", "info"],
      "default": "low",
      "description": "리포트할 최소 심각도"
    }
  },
  "required": ["code"]
}
```

**출력 형식 (Output)**:

```json
{
  "scan_id": "uuid",
  "timestamp": "ISO 8601",
  "summary": {
    "total_issues": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0,
    "risk_score": 8.5
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "SQL Injection via String Concatenation",
      "severity": "critical",
      "confidence": "high",
      "category": "A03:2021-Injection",
      "cwe_id": "CWE-89",
      "cvss_score": 9.8,
      "location": {
        "start_line": 15,
        "end_line": 17,
        "start_column": 5,
        "end_column": 68
      },
      "vulnerable_code": "const query = `SELECT * FROM users WHERE id = ${userId}`;",
      "description": "사용자 입력이 SQL 쿼리에 직접 삽입되어 SQL 인젝션 공격에 노출됩니다.",
      "attack_scenario": "공격자가 userId에 `1 OR 1=1; DROP TABLE users;--`를 입력하면 전체 테이블이 삭제될 수 있습니다.",
      "impact": "데이터 유출, 데이터 변조, 데이터 삭제, 인증 우회",
      "remediation": {
        "description": "파라미터화된 쿼리(Prepared Statement)를 사용하세요.",
        "secure_code": "const query = 'SELECT * FROM users WHERE id = ?';\ndb.query(query, [userId]);",
        "references": [
          "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
        ]
      }
    }
  ],
  "secure_suggestions": [
    "입력값 검증 미들웨어를 추가하세요 (예: express-validator, zod)",
    "ORM 사용을 권장합니다 (예: Prisma, TypeORM)"
  ]
}
```

**분석 흐름**:

```
Input Code → Language Detection → AST Parsing → Rule Matching
     → Taint Analysis → Data Flow Analysis → Severity Calculation
     → Result Aggregation → Output
```

---

### 6.2 FT-02: `scan_file` - 파일 단위 스캔

**입력 파라미터**:

```json
{
  "type": "object",
  "properties": {
    "file_path": {
      "type": "string",
      "description": "스캔할 파일의 절대/상대 경로"
    },
    "rule_sets": {
      "type": "array",
      "items": { "type": "string" },
      "default": ["owasp", "cwe-top25"],
      "description": "적용할 룰셋 목록"
    },
    "exclude_rules": {
      "type": "array",
      "items": { "type": "string" },
      "description": "제외할 룰 ID 목록"
    },
    "include_info": {
      "type": "boolean",
      "default": false,
      "description": "정보성(info) 수준 이슈 포함 여부"
    }
  },
  "required": ["file_path"]
}
```

---

### 6.3 FT-03: `scan_project` - 프로젝트 전체 스캔

**입력 파라미터**:

```json
{
  "type": "object",
  "properties": {
    "project_path": {
      "type": "string",
      "description": "프로젝트 루트 디렉토리 경로"
    },
    "scan_targets": {
      "type": "array",
      "items": { "type": "string" },
      "description": "스캔 대상 하위 경로 (미지정 시 전체)"
    },
    "exclude_paths": {
      "type": "array",
      "items": { "type": "string" },
      "default": ["node_modules", ".git", "dist", "build", "__pycache__"],
      "description": "제외할 디렉토리/파일 패턴"
    },
    "max_file_size_kb": {
      "type": "number",
      "default": 500,
      "description": "스캔 대상 최대 파일 크기 (KB)"
    },
    "parallel_workers": {
      "type": "number",
      "default": 4,
      "description": "병렬 분석 워커 수"
    }
  },
  "required": ["project_path"]
}
```

---

### 6.4 FT-04: `check_dependency` - 의존성 취약점 검사

**입력 파라미터**:

```json
{
  "type": "object",
  "properties": {
    "manifest_path": {
      "type": "string",
      "description": "매니페스트 파일 경로 (package.json, requirements.txt, pom.xml 등)"
    },
    "lock_file_path": {
      "type": "string",
      "description": "락 파일 경로 (선택, 정확한 버전 분석용)"
    },
    "include_transitive": {
      "type": "boolean",
      "default": true,
      "description": "간접 의존성 포함 여부"
    },
    "severity_filter": {
      "type": "string",
      "enum": ["critical", "high", "medium", "low"],
      "default": "medium",
      "description": "리포트할 최소 심각도"
    }
  },
  "required": ["manifest_path"]
}
```

**출력 형식**:

```json
{
  "scan_id": "uuid",
  "manifest": "package.json",
  "total_dependencies": 145,
  "vulnerable_count": 3,
  "vulnerabilities": [
    {
      "package": "lodash",
      "installed_version": "4.17.15",
      "vulnerable_range": "<4.17.21",
      "patched_version": "4.17.21",
      "severity": "high",
      "cve_id": "CVE-2021-23337",
      "cwe_id": "CWE-77",
      "title": "Command Injection in lodash",
      "description": "lodash의 template 함수에서 명령 주입 취약점",
      "exploit_available": true,
      "fix_command": "npm install lodash@4.17.21",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
    }
  ],
  "recommendations": [
    "lodash를 4.17.21 이상으로 업그레이드하세요",
    "사용하지 않는 의존성 3개를 제거하는 것을 권장합니다"
  ]
}
```

---

### 6.5 FT-05: `generate_secure_code` - 시큐어 코드 생성

**입력 파라미터**:

```json
{
  "type": "object",
  "properties": {
    "vulnerable_code": {
      "type": "string",
      "description": "취약한 원본 코드 (선택, 변환 모드)"
    },
    "task": {
      "type": "string",
      "description": "생성할 기능 설명 (예: 'JWT 인증 미들웨어', 'SQL 쿼리 빌더')"
    },
    "language": {
      "type": "string",
      "enum": ["javascript", "typescript", "python", "java"]
    },
    "framework": {
      "type": "string",
      "description": "대상 프레임워크"
    },
    "security_requirements": {
      "type": "array",
      "items": { "type": "string" },
      "description": "충족해야 할 보안 요구사항 목록"
    }
  },
  "required": ["language"]
}
```

**동작 모드**:

| 모드 | 조건 | 동작 |
|---|---|---|
| **변환 모드** | `vulnerable_code` 제공 | 취약한 코드를 안전한 코드로 변환 |
| **생성 모드** | `task` 제공 | 처음부터 시큐어 코드 생성 |
| **하이브리드 모드** | 둘 다 제공 | 취약 코드 참고하여 안전한 코드 재생성 |

---

### 6.6 FT-06: `explain_vulnerability` - 취약점 상세 설명

**입력 파라미터**:

```json
{
  "type": "object",
  "properties": {
    "vulnerability_id": {
      "type": "string",
      "description": "스캔 결과의 취약점 ID 또는 CWE/CVE ID"
    },
    "code_context": {
      "type": "string",
      "description": "취약점이 존재하는 코드 컨텍스트"
    },
    "detail_level": {
      "type": "string",
      "enum": ["beginner", "intermediate", "expert"],
      "default": "intermediate",
      "description": "설명 상세도 (초급/중급/고급)"
    },
    "include_demo": {
      "type": "boolean",
      "default": true,
      "description": "공격 데모 코드 포함 여부"
    }
  },
  "required": ["vulnerability_id"]
}
```

**출력 포함 사항**:
- 취약점 개요 (한 줄 요약)
- 기술적 상세 설명
- 공격 시나리오 (단계별)
- 실제 공격 시 PoC (Proof of Concept) 예시
- 영향 범위 (CIA Triad 기준)
- 수정 방법 (코드 포함)
- 예방 방법 (체크리스트)
- 관련 참고자료

---

### 6.7 FT-07: `audit_config` - 설정 파일 보안 감사

**스캔 대상 설정 파일**:

| 파일 유형 | 검사 항목 |
|---|---|
| `.env`, `.env.*` | 하드코딩된 시크릿, 안전하지 않은 기본값 |
| `docker-compose.yml` | 권한 설정, 볼륨 마운트, 네트워크 노출 |
| `Dockerfile` | 루트 실행, 불필요 패키지, 멀티스테이지 빌드 |
| `nginx.conf` | 보안 헤더, TLS 설정, 디렉토리 리스팅 |
| `tsconfig.json` | strict 모드 설정 |
| `next.config.js` | 보안 관련 설정 검증 |
| `CORS 설정` | 와일드카드 사용, 허용 도메인 검증 |

---

### 6.8 FT-08: `check_security_headers` - HTTP 보안 헤더 검사

**검사 대상 헤더**:

| 헤더 | 권장 설정 | 심각도 |
|---|---|---|
| `Content-Security-Policy` | 존재 및 적절한 정책 | Critical |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | High |
| `X-Content-Type-Options` | `nosniff` | Medium |
| `X-Frame-Options` | `DENY` 또는 `SAMEORIGIN` | High |
| `X-XSS-Protection` | `0` (CSP로 대체) | Low |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Medium |
| `Permissions-Policy` | 불필요 기능 비활성화 | Medium |
| `Cache-Control` | 민감 페이지 `no-store` | Medium |

---

### 6.9 FT-09: `generate_report` - 보안 리포트 생성

**출력 형식**:

| 형식 | 용도 | 표준 |
|---|---|---|
| **SARIF** | CI/CD 통합, GitHub Code Scanning | OASIS SARIF 2.1.0 |
| **JSON** | 프로그래밍 연동 | 자체 스키마 |
| **HTML** | 사람이 읽는 보고서 | 자체 템플릿 |
| **Markdown** | 문서 통합 | CommonMark |

---

## 8. MCP 리소스(Resource) 상세 명세

### 7.1 FR-01: OWASP Top 10 가이드

**URI 패턴**: `secureguard://owasp/top10/{year}`

**지원 연도**: 2021 (현행)

**데이터 구조** (각 항목):

```json
{
  "id": "A01:2021",
  "name": "Broken Access Control",
  "name_ko": "취약한 접근 제어",
  "description": "...",
  "prevalence": "94% of applications tested",
  "cwes_mapped": ["CWE-200", "CWE-201", "CWE-352"],
  "attack_vectors": ["..."],
  "prevention": ["..."],
  "example_scenarios": ["..."],
  "code_examples": {
    "vulnerable": { "javascript": "...", "python": "..." },
    "secure": { "javascript": "...", "python": "..." }
  }
}
```

### 7.2 FR-02: CWE 취약점 데이터베이스

**URI 패턴**: `secureguard://cwe/{id}`

로컬에 Top 50 CWE를 내장하고, 나머지는 온라인 조회 (캐싱).

### 7.3 FR-03: 시큐어코딩 패턴 사전

**URI 패턴**: `secureguard://patterns/{language}/{category}`

**카테고리 목록**:

| Category | 설명 |
|---|---|
| `authentication` | 인증 (로그인, 세션, JWT, OAuth) |
| `authorization` | 인가 (RBAC, ABAC, 리소스 접근 제어) |
| `input-validation` | 입력 검증 (화이트리스트, 정규식, 스키마) |
| `output-encoding` | 출력 인코딩 (HTML, URL, JS, CSS) |
| `cryptography` | 암호화 (해싱, 대칭/비대칭, 키 관리) |
| `error-handling` | 에러 처리 (정보 노출 방지) |
| `logging` | 보안 로깅 (민감정보 마스킹) |
| `file-upload` | 파일 업로드 (검증, 저장, 서빙) |
| `api-security` | API 보안 (Rate limiting, API Key, CORS) |
| `database` | DB 보안 (파라미터 쿼리, ORM, 접근 제어) |
| `session` | 세션 관리 (생성, 만료, 고정 공격 방지) |
| `csrf-protection` | CSRF 방어 (토큰, SameSite, Double Submit) |

---

## 9. MCP 프롬프트(Prompt) 상세 명세

### 8.1 FP-01: `security_code_review` - 보안 코드리뷰

**프롬프트 인자**:

```json
{
  "arguments": [
    {
      "name": "code",
      "description": "리뷰할 코드",
      "required": true
    },
    {
      "name": "review_depth",
      "description": "리뷰 깊이",
      "required": false
    }
  ]
}
```

**생성되는 프롬프트 템플릿**:

```
당신은 20년 경력의 웹 보안 전문가입니다.
아래 코드를 보안 관점에서 철저히 리뷰하세요.

[리뷰 체크리스트]
1. 입력값 검증 (모든 외부 입력)
2. 인증/인가 (접근 제어 적절성)
3. 인젝션 (SQL, NoSQL, OS Command, LDAP)
4. XSS (Reflected, Stored, DOM-based)
5. CSRF (상태 변경 요청 보호)
6. 민감정보 노출 (로그, 에러, 응답)
7. 암호화 (적절한 알고리즘, 키 관리)
8. 에러 처리 (정보 누출 방지)
9. 비즈니스 로직 (Race condition, 권한 상승)
10. 설정 보안 (디버그 모드, 기본 설정)

[코드]
{code}

각 취약점에 대해:
- 심각도 (Critical/High/Medium/Low/Info)
- 위치 (라인 번호)
- 취약점 설명
- 공격 시나리오
- 수정 코드
를 제시하세요.
```

### 8.2 FP-02: `threat_modeling` - STRIDE 위협 모델링

사용자가 시스템 구조를 설명하면, STRIDE 프레임워크 기반으로 위협을 식별한다.

| STRIDE | 위협 | 분석 관점 |
|---|---|---|
| **S**poofing | 신원 위장 | 인증 메커니즘 |
| **T**ampering | 데이터 변조 | 무결성 검증 |
| **R**epudiation | 부인 | 감사 로그 |
| **I**nformation Disclosure | 정보 노출 | 데이터 보호 |
| **D**enial of Service | 서비스 거부 | 가용성 보호 |
| **E**levation of Privilege | 권한 상승 | 인가 메커니즘 |

---

## 10. 보안 탐지 룰 체계

### 9.1 룰 분류 체계

```
Rule ID 형식: SCG-{CATEGORY}-{SUBCATEGORY}-{NUMBER}

예시: SCG-INJ-SQL-001 (인젝션 > SQL > 첫 번째 룰)
```

### 9.2 OWASP Top 10 (2021) 매핑

| OWASP | 카테고리 코드 | 내장 룰 수 (Phase 1) |
|---|---|---|
| A01: Broken Access Control | `SCG-BAC` | 15 |
| A02: Cryptographic Failures | `SCG-CRY` | 12 |
| A03: Injection | `SCG-INJ` | 20 |
| A04: Insecure Design | `SCG-ISD` | 8 |
| A05: Security Misconfiguration | `SCG-MCF` | 18 |
| A06: Vulnerable Components | `SCG-VUL` | 5 (의존성 검사 연동) |
| A07: Auth Failures | `SCG-AUF` | 14 |
| A08: Data Integrity Failures | `SCG-DIF` | 10 |
| A09: Logging & Monitoring | `SCG-LOG` | 8 |
| A10: SSRF | `SCG-SSR` | 6 |
| **합계** | | **116** |

### 9.3 룰 정의 포맷 (YAML)

```yaml
rule:
  id: SCG-INJ-SQL-001
  title: "SQL Injection via String Concatenation"
  title_ko: "문자열 결합을 통한 SQL 인젝션"
  severity: critical
  confidence: high
  category: A03:2021-Injection
  cwe: CWE-89
  cvss: 9.8
  
  description:
    en: "User input is directly concatenated into SQL query string"
    ko: "사용자 입력이 SQL 쿼리 문자열에 직접 결합됩니다"
  
  languages: [javascript, typescript, python, java]
  
  detection:
    patterns:
      - type: ast
        node: TemplateLiteral
        contains: 
          - "SELECT"
          - "INSERT"
          - "UPDATE"
          - "DELETE"
        with_tainted_expression: true
      
      - type: regex
        pattern: '(SELECT|INSERT|UPDATE|DELETE)\s.*\+\s*\w+'
        scope: string_concatenation
    
    taint_sources:
      - "req.params.*"
      - "req.query.*"
      - "req.body.*"
      - "request.args.*"
      - "request.form.*"
    
    taint_sinks:
      - "db.query($TAINTED)"
      - "connection.execute($TAINTED)"
      - "cursor.execute($TAINTED)"
  
  false_positive_filters:
    - pattern: ".*\\.escape\\(.*\\)"
    - pattern: ".*parameterized.*"
  
  remediation:
    description_ko: "파라미터화된 쿼리(Prepared Statement)를 사용하세요."
    secure_examples:
      javascript: |
        // ✅ 안전: 파라미터화된 쿼리
        const result = await db.query(
          'SELECT * FROM users WHERE id = $1',
          [userId]
        );
      python: |
        # ✅ 안전: 파라미터화된 쿼리
        cursor.execute(
            "SELECT * FROM users WHERE id = %s",
            (user_id,)
        )
    references:
      - "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
      - "https://cwe.mitre.org/data/definitions/89.html"
  
  tags: [sql, injection, database, owasp-top10, critical]
```

### 9.4 심각도 산정 기준

| 심각도 | CVSS 범위 | 기준 | 예시 |
|---|---|---|---|
| **Critical** | 9.0 - 10.0 | 원격 코드 실행, 인증 우회, 전체 데이터 유출 | SQL Injection, RCE, Auth Bypass |
| **High** | 7.0 - 8.9 | 민감 데이터 노출, 권한 상승, XSS (Stored) | Stored XSS, IDOR, Path Traversal |
| **Medium** | 4.0 - 6.9 | 제한적 정보 노출, 설정 미흡 | CSRF, Reflected XSS, Weak Crypto |
| **Low** | 0.1 - 3.9 | 간접적 위험, 보안 강화 권장 | Missing Headers, Verbose Errors |
| **Info** | 0.0 | 보안 개선 제안, 베스트 프랙티스 | Code Quality, Best Practice |

---

## 11. 데이터 모델

### 10.1 핵심 엔티티

```
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│   ScanResult  │───►│ Vulnerability │───►│   Remediation    │
│              │    │              │    │                  │
│ scan_id      │    │ vuln_id      │    │ remediation_id   │
│ timestamp    │    │ scan_id (FK) │    │ vuln_id (FK)     │
│ target_type  │    │ title        │    │ description      │
│ target_path  │    │ severity     │    │ secure_code      │
│ language     │    │ confidence   │    │ references       │
│ framework    │    │ category     │    └──────────────────┘
│ total_issues │    │ cwe_id       │
│ risk_score   │    │ cvss_score   │
└──────────────┘    │ location     │
                    │ description  │
                    │ attack_info  │
                    └──────────────┘

┌──────────────┐    ┌──────────────┐
│     Rule      │    │  RuleSet     │
│              │    │              │
│ rule_id      │    │ set_id       │
│ title        │    │ name         │
│ severity     │    │ description  │
│ category     │    │ rules[]      │
│ cwe          │    │ enabled      │
│ detection    │    └──────────────┘
│ remediation  │
│ languages[]  │
│ enabled      │
└──────────────┘

┌──────────────────┐
│  DependencyVuln   │
│                  │
│ id               │
│ package_name     │
│ version_range    │
│ patched_version  │
│ cve_id           │
│ severity         │
│ exploit_available│
└──────────────────┘
```

### 10.2 로컬 캐시 테이블 (SQLite)

```sql
-- 스캔 이력 (민감 코드는 저장하지 않음)
CREATE TABLE scan_history (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    target_type TEXT NOT NULL,      -- 'code' | 'file' | 'project'
    target_hash TEXT NOT NULL,       -- 대상 코드의 SHA-256 해시
    language TEXT,
    framework TEXT,
    total_issues INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0.0
);

-- CVE 캐시 (외부 API 조회 결과)
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,              -- JSON
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- 의존성 취약점 캐시
CREATE TABLE dependency_vuln_cache (
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,         -- 'npm' | 'pip' | 'maven'
    data TEXT NOT NULL,              -- JSON
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (package_name, ecosystem)
);
```

---

## 12. 외부 인터페이스

### 12.1 외부 API 연동

| API | 용도 | 필수/선택 | 인증 |
|---|---|---|---|
| **OSV.dev API** | 의존성 취약점 조회 | 선택 | 불필요 |
| **NVD API** | CVE 상세 정보 | 선택 | API Key (무료) |
| **GitHub Advisory DB** | GitHub 보안 권고 | 선택 | GitHub Token |
| **OpenAI API** | Deep 모드 LLM 분석 | 선택 | API Key |
| **Anthropic API** | Deep 모드 LLM 분석 | 선택 | API Key |
| **Ollama (로컬)** | Deep 모드 로컬 LLM 분석 | 선택 | 불필요 |

모든 외부 API 연동은 **선택사항**이며, 오프라인에서도 내장 룰과 로컬 DB로 핵심 기능이 동작한다.

### 12.2 CI/CD 통합 인터페이스

```bash
# GitHub Actions 예시
- name: SecureCode Guardian Scan
  uses: securecode-guardian/action@v1
  with:
    scan_path: ./src
    severity_threshold: high
    fail_on_critical: true
    report_format: sarif
    
# SARIF 업로드 (GitHub Code Scanning)
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secureguard-report.sarif
```

---

## 13. LLM 연동 상세 설계

> **v1.1 신규 섹션** - MCP 내부에서 LLM을 활용하는 구체적 기술 설계

### 13.1 LLM 분석 파이프라인

```
┌─────────────────────────────────────────────────────────────────┐
│                    LLM Analysis Pipeline                         │
│                                                                   │
│  ┌─────────┐   ┌──────────┐   ┌─────────┐   ┌───────────────┐  │
│  │ 입력     │──►│ 전처리    │──►│ LLM     │──►│ 후처리         │  │
│  │ 코드     │   │ (마스킹/  │   │ 호출    │   │ (검증/구조화)  │  │
│  │ + 룰 결과│   │  컨텍스트)│   │         │   │               │  │
│  └─────────┘   └──────────┘   └─────────┘   └───────────────┘  │
│                                                                   │
│  전처리 단계:                                                     │
│  1. 민감정보 마스킹 (API Key, Password → [REDACTED_SECRET_1])    │
│  2. 코드 축소 (취약점 주변 ±20줄만 추출)                          │
│  3. 룰 기반 결과 첨부 (LLM이 참고하도록)                          │
│  4. 프로젝트 컨텍스트 주입 (프레임워크, DB, 인프라 정보)           │
│                                                                   │
│  후처리 단계:                                                     │
│  1. JSON 응답 파싱 및 유효성 검증                                  │
│  2. CWE/CVE ID 실존 여부 확인 (환각 방지)                         │
│  3. 심각도 재산정 (CVSS 기준 정규화)                               │
│  4. 마스킹 원복 (리포트용)                                         │
│  5. 룰 기반 결과와 병합                                            │
└─────────────────────────────────────────────────────────────────┘
```

### 13.2 LLM 호출 인터페이스

```typescript
interface LLMAnalysisRequest {
  code: string;                    // 마스킹 처리된 코드
  language: string;
  framework?: string;
  ruleBasedFindings: Finding[];    // Stage 1 룰 분석 결과
  analysisType: 
    | 'deep_scan'                  // 심층 취약점 분석
    | 'false_positive_filter'      // 오탐 필터링
    | 'business_logic'             // 비즈니스 로직 취약점
    | 'remediation'                // 수정 코드 생성
    | 'explain';                   // 취약점 설명 생성
  contextHints?: {
    projectType: string;           // 'web-api' | 'spa' | 'ssr' | 'cli'
    authMethod?: string;           // 'jwt' | 'session' | 'oauth'
    database?: string;             // 'mysql' | 'postgresql' | 'mongodb'
  };
}

interface LLMAnalysisResponse {
  findings: LLMFinding[];
  falsePositiveCandidates: string[];   // 오탐으로 판단한 룰 결과 ID
  businessLogicConcerns: string[];
  overallAssessment: string;
  confidence: number;                   // 0.0 ~ 1.0
  tokensUsed: { input: number; output: number };
  model: string;
  latencyMs: number;
}

interface LLMFinding {
  title: string;
  description: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  cweId?: string;                      // 후처리에서 검증됨
  location: CodeLocation;
  attackScenario: string;
  remediation: {
    description: string;
    secureCode: string;
  };
  source: 'llm';                       // 룰 기반과 구분
}
```

### 13.3 환각(Hallucination) 방지 전략

LLM의 가장 큰 리스크는 **존재하지 않는 취약점을 보고**하는 것이다.

| 전략 | 구현 방법 | 효과 |
|---|---|---|
| **앵커링** | 룰 기반 결과를 프롬프트에 포함하여 LLM이 참고 | 근거 있는 분석 유도 |
| **ID 검증** | LLM이 언급한 CWE/CVE ID를 로컬 DB에서 실존 확인 | 가짜 ID 차단 |
| **구조 강제** | JSON Schema로 응답 형식 강제 | 자유형 텍스트 방지 |
| **온도 제어** | temperature 0.1~0.3 | 창의적 응답 억제 |
| **자기 검증** | "확실하지 않으면 confidence: low로 표시" 프롬프트 | 과신 방지 |
| **이중 검증** | LLM이 생성한 수정 코드를 룰 엔진으로 재스캔 | 안전하지 않은 수정 방지 |

```typescript
// 환각 방지 후처리 예시
class HallucinationGuard {
  async validate(llmResponse: LLMAnalysisResponse): Promise<ValidatedResponse> {
    const validated = { ...llmResponse };
    
    for (const finding of validated.findings) {
      if (finding.cweId) {
        const exists = await this.cweDb.exists(finding.cweId);
        if (!exists) {
          finding.cweId = undefined;
          finding.confidence = 'low';
          finding.title += ' [CWE ID 미확인]';
        }
      }
      
      if (finding.remediation?.secureCode) {
        const rescanResult = await this.ruleEngine.scan(finding.remediation.secureCode);
        if (rescanResult.hasVulnerabilities) {
          finding.remediation.secureCode = undefined;
          finding.remediation.description += 
            '\n⚠️ 자동 생성 수정 코드에서 추가 취약점이 발견되어 제거되었습니다.';
        }
      }
    }
    
    return validated;
  }
}
```

### 13.4 민감정보 마스킹 상세

LLM에 코드를 전송하기 전 반드시 마스킹 처리한다.

```typescript
// 마스킹 대상 및 패턴
const MASKING_RULES = [
  // API Keys & Tokens
  { pattern: /(?:api[_-]?key|token|secret)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    replacement: '[REDACTED_API_KEY]' },
  
  // AWS Credentials
  { pattern: /AKIA[0-9A-Z]{16}/g,
    replacement: '[REDACTED_AWS_KEY]' },
  
  // Database Connection Strings
  { pattern: /(?:mongodb|mysql|postgres|redis):\/\/[^\s'"]+/gi,
    replacement: '[REDACTED_DB_URL]' },
  
  // JWT Tokens
  { pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g,
    replacement: '[REDACTED_JWT]' },
  
  // Private Keys
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END/g,
    replacement: '[REDACTED_PRIVATE_KEY]' },
  
  // IP Addresses (내부망)
  { pattern: /(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/g,
    replacement: '[REDACTED_INTERNAL_IP]' },
];
```

### 13.5 LLM 비용 제어 메커니즘

```typescript
interface CostControlConfig {
  daily_token_limit: number;       // 일일 토큰 한도 (기본: 100,000)
  monthly_token_limit: number;     // 월간 토큰 한도
  max_input_tokens: number;        // 단일 요청 최대 입력 토큰 (기본: 4,096)
  max_output_tokens: number;       // 단일 요청 최대 출력 토큰 (기본: 2,048)
  cache_identical_code: boolean;   // 동일 코드 해시 캐시 (기본: true)
  cache_ttl_minutes: number;       // 캐시 유효기간 (기본: 60분)
  fallback_on_limit: 'lite' | 'error';  // 한도 초과 시 동작
}

// 사용량 추적 테이블
// CREATE TABLE llm_usage (
//     date TEXT NOT NULL,
//     provider TEXT NOT NULL,
//     model TEXT NOT NULL,
//     input_tokens INTEGER DEFAULT 0,
//     output_tokens INTEGER DEFAULT 0,
//     request_count INTEGER DEFAULT 0,
//     estimated_cost_usd REAL DEFAULT 0.0,
//     PRIMARY KEY (date, provider, model)
// );
```

### 13.6 LLM Provider별 최적 프롬프트 전략

같은 분석이라도 LLM Provider별로 프롬프트 전략이 다르다.

| Provider | 특성 | 프롬프트 전략 |
|---|---|---|
| **Claude (Anthropic)** | XML 태그 이해 우수, 긴 컨텍스트 | `<vulnerability>`, `<code>` 태그 활용, 상세 체인오브소트 |
| **GPT-4 (OpenAI)** | JSON 모드 지원, Function Calling | `response_format: json_object`, 구조화 출력 강제 |
| **Ollama (로컬)** | 모델별 차이, 토큰 제한적 | 간결한 프롬프트, 핵심만 요청, few-shot 예시 포함 |

```typescript
// Provider별 프롬프트 빌더
class PromptBuilder {
  build(request: LLMAnalysisRequest, provider: string): ProviderPrompt {
    switch (provider) {
      case 'anthropic':
        return this.buildClaudePrompt(request);
      case 'openai':
        return this.buildOpenAIPrompt(request);
      case 'ollama':
        return this.buildOllamaPrompt(request);
    }
  }
  
  private buildClaudePrompt(req: LLMAnalysisRequest): ProviderPrompt {
    return {
      system: SECURITY_ANALYST_SYSTEM_PROMPT,
      messages: [{
        role: 'user',
        content: `
<task>${req.analysisType}</task>
<language>${req.language}</language>
<framework>${req.framework || 'unknown'}</framework>

<code>
${req.code}
</code>

<rule_based_findings>
${JSON.stringify(req.ruleBasedFindings, null, 2)}
</rule_based_findings>

<instructions>
위 코드에서 룰 기반 분석으로 발견되지 않은 추가 보안 취약점을 분석하세요.
특히 비즈니스 로직 취약점, Race Condition, 권한 상승 가능성에 집중하세요.
룰 기반 결과 중 오탐(false positive)이 있다면 지적하세요.
</instructions>`
      }]
    };
  }
}
```

### 13.7 오프라인/로컬 전용 모드

기업 보안 정책상 외부 API 사용이 불가한 환경을 위한 완전 로컬 모드:

```
[완전 로컬 모드 스택]

MCP Server (Node.js)
    │
    ├── Stage 1: 룰 기반 분석 (항상 로컬)
    │
    └── Stage 2: Ollama 로컬 LLM (선택)
         │
         ├── deepseek-coder-v2 (6.7B) - 가벼움, 기본 분석
         ├── codellama:34b - 정밀 분석, GPU 필요
         └── qwen2.5-coder:32b - 다국어, 한국어 지원
         
외부 네트워크 연결: 없음
코드 유출 위험: 없음
```

| 항목 | 외부 API 모드 | 로컬 전용 모드 |
|---|---|---|
| 코드 외부 전송 | O (마스킹 후) | X |
| 분석 품질 | 높음 (GPT-4/Claude) | 중간 (로컬 모델 의존) |
| 응답 속도 | 네트워크 + 모델 추론 | 로컬 추론만 |
| 비용 | API 과금 | GPU 전기료만 |
| 오프라인 동작 | X | O |
| 기업 보안 정책 | 검토 필요 | 통과 |

---

## 14. 제약사항 및 전제조건

### 14.1 기술적 제약사항

| ID | 제약사항 | 영향 | 대응 방안 |
|---|---|---|---|
| TC-01 | 정적 분석 한계로 런타임 취약점 탐지 불가 | 일부 취약점 미탐지 | LLM 추론으로 부분 보완 + DAST 도구 권고 |
| TC-02 | AST 파싱 실패 시 (문법 오류) 분석 불가 | 미완성 코드 분석 제한 | Regex 폴백 + LLM 폴백 |
| TC-03 | 난독화된 코드 분석 한계 | 난독화 코드 정탐률 저하 | 난독화 탐지 경고 |
| TC-04 | 대규모 프로젝트 스캔 시 시간 소요 | UX 저하 | 증분 스캔, 병렬 처리 |
| TC-05 | 외부 API 미연결 시 CVE 데이터 제한 | 최신 CVE 미반영 | 로컬 DB 주기적 업데이트 |
| TC-06 | LLM 환각으로 잘못된 취약점 보고 가능 | 오탐 증가 | 환각 방지 파이프라인 (13.3절) |
| TC-07 | LLM API 비용 누적 | 운영비 증가 | 비용 제어 메커니즘 (13.5절) |
| TC-08 | LLM 응답 비결정성 | 동일 코드 다른 결과 | 캐싱 + 낮은 temperature + 룰 앵커링 |
| TC-09 | 로컬 LLM은 GPU 필요 | 하드웨어 의존 | CPU 모드 폴백 (느림) + Lite 모드 기본 |

### 14.2 전제조건

| ID | 전제조건 |
|---|---|
| PC-01 | Node.js 18 이상이 설치되어 있어야 한다 |
| PC-02 | MCP 지원 IDE/클라이언트가 필요하다 (Cursor, Claude Desktop 등) |
| PC-03 | 분석 대상 코드가 지원 언어/프레임워크여야 한다 |
| PC-04 | 의존성 검사는 매니페스트 파일이 존재해야 한다 |
| PC-05 | Deep 모드 사용 시: LLM Provider API 키 또는 Ollama 설치 필요 |
| PC-06 | 로컬 LLM 사용 시: 최소 8GB RAM, 권장 16GB+ RAM + NVIDIA GPU |

---

## 15. 릴리스 계획

### Phase 1: MVP (v0.1.0) - 8주

| 주차 | 마일스톤 | 산출물 |
|---|---|---|
| W1-2 | 프로젝트 셋업 + MCP 서버 스캐폴딩 | 기본 MCP 서버, 빌드 파이프라인 |
| W3-4 | `scan_code` + `scan_file` 구현 (Lite 모드) | 코드 스캔 MVP (JS/TS, 룰 기반만) |
| W5 | `check_dependency` 구현 | npm 의존성 검사 |
| W6 | `generate_secure_code` 구현 | 시큐어 코드 변환 |
| W7 | OWASP Top 10 리소스 + 프롬프트 | MCP Resources/Prompts |
| W8 | 테스트 + 버그 수정 + 문서화 | 릴리스 v0.1.0 |

**MVP 범위**: JS/TS + 50개 핵심 룰 + Lite 모드 + 기본 4 Tools + 2 Resources + 1 Prompt

### Phase 2: LLM 통합 (v0.2.0) - 6주 ← **변경됨**

- **LLM Provider 추상화 레이어 구현** (Ollama/OpenAI/Anthropic)
- **Deep 모드 분석 파이프라인 구현**
- 민감정보 마스킹 모듈
- 환각 방지 파이프라인
- LLM 비용 제어 메커니즘
- Standard/Deep 모드 활성화
- Python/Java 언어 지원

### Phase 3: 고도화 (v1.0.0) - 8주

- Taint Analysis 고도화
- Data Flow Analysis
- LLM 기반 오탐 필터링 정교화
- 외부 API 연동 (NVD, OSV)
- 프레임워크별 룰 (React, Express, FastAPI, Spring)
- SARIF 리포트 출력
- CI/CD 통합 Action
- 다국어 지원 (한/영/일)
- 커스텀 룰 지원

### Phase 4: 엔터프라이즈 (v2.0.0) - 12주

- SSE/Streamable HTTP Transport
- 팀 정책 관리
- 대시보드 웹 UI
- 온프레미스 배포 지원 (로컬 LLM 번들)
- 컴플라이언스 리포트 (PCI-DSS, GDPR, KISA)
- Fine-tuned 보안 특화 모델 지원

---

## 16. 용어 정의

| 용어 | 정의 |
|---|---|
| **MCP** | Model Context Protocol - AI 모델이 외부 도구와 데이터에 접근하기 위한 표준 프로토콜 |
| **Host LLM** | MCP Client 측에서 동작하는 LLM (예: Cursor의 Claude). MCP Tool을 호출하는 주체 |
| **내장 LLM** | MCP Server 내부에서 Deep 분석을 위해 호출하는 LLM (Ollama/OpenAI/Anthropic) |
| **OWASP** | Open Web Application Security Project - 웹 보안 표준 제정 비영리 단체 |
| **CWE** | Common Weakness Enumeration - 소프트웨어 취약점 유형 분류 체계 |
| **CVE** | Common Vulnerabilities and Exposures - 공개된 보안 취약점 고유 식별자 |
| **CVSS** | Common Vulnerability Scoring System - 취약점 심각도 점수 체계 (0~10) |
| **SARIF** | Static Analysis Results Interchange Format - 정적 분석 결과 교환 포맷 |
| **SAST** | Static Application Security Testing - 정적 애플리케이션 보안 테스트 |
| **DAST** | Dynamic Application Security Testing - 동적 애플리케이션 보안 테스트 |
| **AST** | Abstract Syntax Tree - 추상 구문 트리 (코드 구조 분석 기반) |
| **Taint Analysis** | 오염 분석 - 신뢰할 수 없는 입력의 흐름을 추적하는 분석 기법 |
| **Hallucination** | 환각 - LLM이 사실이 아닌 정보를 그럴듯하게 생성하는 현상 |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege |
| **CIA Triad** | Confidentiality, Integrity, Availability - 정보보안 3대 요소 |
| **OSV** | Open Source Vulnerabilities - 오픈소스 취약점 데이터베이스 |
| **NVD** | National Vulnerability Database - 미국 국가 취약점 데이터베이스 |
| **Ollama** | 로컬에서 LLM을 실행할 수 있는 오픈소스 프레임워크 |

---

## 문서 변경 이력

| 버전 | 날짜 | 작성자 | 변경 내용 |
|---|---|---|---|
| v1.0.0 | 2026-02-26 | - | 최초 작성 |
| v1.1.0 | 2026-02-26 | - | LLM 연동 아키텍처 추가 (3장, 13장), 양방향 LLM 통합 설계, 환각 방지, 비용 제어, 로컬 모드 |

---

> **다음 단계**: 본 요구사항명세서를 기반으로 기술 설계 문서(TDD)를 작성하고, Phase 1 MVP 개발을 시작합니다.
