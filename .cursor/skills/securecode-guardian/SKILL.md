---
name: securecode-guardian
description: 시큐어코딩 자동화 워크플로우. 코드 생성 시 보안 블루프린트를 읽고 최적 보안 설계를 반영하여 코드를 작성한 뒤 자동 검증합니다. 만들어줘, 구현해줘, 작성해줘, 코딩해줘, 로그인, 게시판, 회원가입, API, 서버, 페이지, 웹, 검색, 댓글, 업로드 요청 시 적용.
---

# SecureCode Guardian 워크플로우

## 코드 생성 필수 순서 (6단계)

### Step 1: 보안 블루프린트 읽기

`security://blueprints` 리소스를 읽으세요. 기능별 최적 보안 설계가 담겨 있습니다.

- 위협 분석, 필수 보안 요구사항 (우선순위별), 구현 코드, 아키텍처
- 로그인, 회원가입, 게시판, 파일 업로드, 검색, API, 댓글 지원
- **이 블루프린트의 요구사항을 코드에 반드시 반영하세요**

추가 참고 리소스:
- `security://secure-patterns` → 시큐어코딩 패턴 코드
- `security://owasp-top10` → OWASP Top 10 위협
- `security://cwe-database` → CWE 데이터베이스

### Step 2: 위협 분석

```
도구: secure_develop
파라미터: { feature: "로그인" }
```

### Step 3: CVE 검색

```
도구: search_cve
파라미터: { query: "express" }
```

사용할 주요 라이브러리마다 호출하세요.

### Step 4: 코드 작성

블루프린트 + 위협 분석 + CVE 결과를 반영하여 코드를 작성하세요.

핵심: Claude가 보안 블루프린트를 읽고 직접 최적의 보안 기법을 판단하여 적용합니다.

### Step 5: 보안 검증

```
도구: secure_code
파라미터: { code: "작성한 전체 코드", show_comparison: true }
```

### Step 6: 의존성 검사

```
도구: check_dependency
파라미터: { manifest: "package.json 내용", ecosystem: "npm" }
```

## 금지사항

- 보안 블루프린트를 읽지 않고 코드를 작성하는 것
- secure_code 도구 호출 없이 코드를 보여주는 것
- 보안 검증 단계를 생략하는 것
