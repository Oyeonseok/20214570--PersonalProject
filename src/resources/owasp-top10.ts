export interface OwaspItem {
  id: string;
  name: string;
  nameKo: string;
  description: string;
  descriptionKo: string;
  prevalence: string;
  cwes: string[];
  prevention: string[];
  preventionKo: string[];
}

export const OWASP_TOP10_2021: OwaspItem[] = [
  {
    id: 'A01:2021',
    name: 'Broken Access Control',
    nameKo: '취약한 접근 제어',
    description: 'Restrictions on what authenticated users are allowed to do are often not properly enforced.',
    descriptionKo: '인증된 사용자가 할 수 있는 작업에 대한 제한이 제대로 적용되지 않는 경우가 많습니다.',
    prevalence: '94% of applications tested had some form of broken access control',
    cwes: ['CWE-200', 'CWE-201', 'CWE-352', 'CWE-22', 'CWE-425', 'CWE-639'],
    prevention: [
      'Deny by default (except public resources)',
      'Implement access control once and reuse throughout the application',
      'Enforce record ownership',
      'Disable directory listing',
      'Log access control failures and alert admins',
      'Rate limit API access',
    ],
    preventionKo: [
      '기본적으로 접근을 거부하세요 (공개 리소스 제외)',
      '접근 제어를 한 번 구현하고 애플리케이션 전체에서 재사용하세요',
      '레코드 소유권을 적용하세요',
      '디렉토리 리스팅을 비활성화하세요',
      '접근 제어 실패를 로깅하고 관리자에게 알리세요',
      'API 접근 속도를 제한하세요',
    ],
  },
  {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    nameKo: '암호화 실패',
    description: 'Failures related to cryptography which often lead to sensitive data exposure.',
    descriptionKo: '민감한 데이터 노출로 이어지는 암호화 관련 실패입니다.',
    prevalence: 'Notable CWEs included are CWE-259, CWE-327, and CWE-331',
    cwes: ['CWE-259', 'CWE-327', 'CWE-331', 'CWE-321', 'CWE-328'],
    prevention: [
      'Classify data by sensitivity level',
      'Encrypt all sensitive data at rest and in transit',
      'Use strong standard algorithms (AES-256, RSA-2048+)',
      'Use proper key management',
      'Use bcrypt/scrypt/Argon2 for password hashing',
      'Disable caching for sensitive data',
    ],
    preventionKo: [
      '민감도 수준에 따라 데이터를 분류하세요',
      '모든 민감 데이터를 저장 시와 전송 시 암호화하세요',
      '강력한 표준 알고리즘을 사용하세요 (AES-256, RSA-2048+)',
      '적절한 키 관리를 사용하세요',
      '비밀번호 해싱에 bcrypt/scrypt/Argon2를 사용하세요',
      '민감 데이터에 대한 캐싱을 비활성화하세요',
    ],
  },
  {
    id: 'A03:2021',
    name: 'Injection',
    nameKo: '인젝션',
    description: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.',
    descriptionKo: '신뢰할 수 없는 데이터가 명령어나 쿼리의 일부로 인터프리터에 전송될 때 발생합니다.',
    prevalence: '94% of applications were tested for injection with a max incidence rate of 19%',
    cwes: ['CWE-79', 'CWE-89', 'CWE-73', 'CWE-78', 'CWE-94'],
    prevention: [
      'Use parameterized queries / prepared statements',
      'Use positive server-side input validation',
      'Escape special characters',
      'Use LIMIT in SQL queries to prevent mass disclosure',
      'Use ORMs carefully (still possible to inject)',
    ],
    preventionKo: [
      '파라미터화된 쿼리/Prepared Statement를 사용하세요',
      '서버 측 양성(positive) 입력 검증을 사용하세요',
      '특수 문자를 이스케이프하세요',
      '대량 노출 방지를 위해 SQL 쿼리에 LIMIT를 사용하세요',
      'ORM을 신중하게 사용하세요 (여전히 인젝션 가능)',
    ],
  },
  {
    id: 'A04:2021',
    name: 'Insecure Design',
    nameKo: '안전하지 않은 설계',
    description: 'Risks related to design and architectural flaws.',
    descriptionKo: '설계 및 아키텍처 결함과 관련된 위험입니다.',
    prevalence: 'New category for 2021',
    cwes: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'],
    prevention: [
      'Use threat modeling for critical flows',
      'Integrate security in the SDLC',
      'Use secure design patterns',
      'Write unit and integration tests for security',
      'Segregate tiers at network level',
    ],
    preventionKo: [
      '주요 흐름에 위협 모델링을 사용하세요',
      'SDLC에 보안을 통합하세요',
      '보안 설계 패턴을 사용하세요',
      '보안을 위한 단위/통합 테스트를 작성하세요',
      '네트워크 수준에서 계층을 분리하세요',
    ],
  },
  {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    nameKo: '보안 설정 오류',
    description: 'Missing or incorrect security hardening across the application stack.',
    descriptionKo: '애플리케이션 스택 전반에 걸친 보안 강화 누락 또는 오류입니다.',
    prevalence: '90% of applications were tested for misconfiguration',
    cwes: ['CWE-16', 'CWE-611', 'CWE-1004'],
    prevention: [
      'Automated hardening process',
      'Minimal platform without unnecessary features',
      'Review and update configurations regularly',
      'Segmented application architecture',
      'Send security directives to clients (headers)',
    ],
    preventionKo: [
      '자동화된 보안 강화 프로세스를 구축하세요',
      '불필요한 기능이 없는 최소 플랫폼을 사용하세요',
      '설정을 정기적으로 검토하고 업데이트하세요',
      '분리된 애플리케이션 아키텍처를 사용하세요',
      '클라이언트에 보안 지시를 전송하세요 (헤더)',
    ],
  },
  {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    nameKo: '취약하고 오래된 컴포넌트',
    description: 'Using components with known vulnerabilities.',
    descriptionKo: '알려진 취약점이 있는 컴포넌트를 사용합니다.',
    prevalence: 'Only category with no CVEs mapped',
    cwes: ['CWE-1104'],
    prevention: [
      'Remove unused dependencies',
      'Continuously inventory component versions',
      'Monitor CVE and NVD for vulnerabilities',
      'Only obtain components from official sources via secure links',
      'Monitor for unmaintained libraries',
    ],
    preventionKo: [
      '사용하지 않는 의존성을 제거하세요',
      '컴포넌트 버전을 지속적으로 관리하세요',
      'CVE 및 NVD에서 취약점을 모니터링하세요',
      '보안 링크를 통해 공식 소스에서만 컴포넌트를 받으세요',
      '관리되지 않는 라이브러리를 모니터링하세요',
    ],
  },
  {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    nameKo: '식별 및 인증 실패',
    description: 'Weaknesses in authentication and session management.',
    descriptionKo: '인증 및 세션 관리의 취약점입니다.',
    prevalence: 'Previously "Broken Authentication"',
    cwes: ['CWE-297', 'CWE-287', 'CWE-384', 'CWE-798'],
    prevention: [
      'Implement multi-factor authentication',
      'Do not deploy with default credentials',
      'Implement weak password checks',
      'Limit failed login attempts (rate limiting)',
      'Use server-side session management',
    ],
    preventionKo: [
      '다중 인증(MFA)을 구현하세요',
      '기본 자격증명으로 배포하지 마세요',
      '취약한 비밀번호 검사를 구현하세요',
      '로그인 실패 시도를 제한하세요 (Rate Limiting)',
      '서버 측 세션 관리를 사용하세요',
    ],
  },
  {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    nameKo: '소프트웨어 및 데이터 무결성 실패',
    description: 'Code and infrastructure that does not protect against integrity violations.',
    descriptionKo: '무결성 위반을 방지하지 않는 코드 및 인프라입니다.',
    prevalence: 'New category for 2021, includes insecure deserialization',
    cwes: ['CWE-502', 'CWE-829'],
    prevention: [
      'Use digital signatures to verify software/data integrity',
      'Ensure libraries are from trusted repositories',
      'Use SRI for CDN resources',
      'Review code and configuration changes',
      'Do not send unsigned/unencrypted serialized data',
    ],
    preventionKo: [
      '디지털 서명으로 소프트웨어/데이터 무결성을 검증하세요',
      '신뢰할 수 있는 저장소의 라이브러리를 사용하세요',
      'CDN 리소스에 SRI를 사용하세요',
      '코드 및 설정 변경을 검토하세요',
      '서명/암호화되지 않은 직렬화 데이터를 전송하지 마세요',
    ],
  },
  {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    nameKo: '보안 로깅 및 모니터링 실패',
    description: 'Without logging and monitoring, breaches cannot be detected.',
    descriptionKo: '로깅 및 모니터링 없이는 침해를 감지할 수 없습니다.',
    prevalence: 'Helps detect, escalate, and respond to active breaches',
    cwes: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
    prevention: [
      'Log all login, access control, and server-side input validation failures',
      'Ensure logs are in a format easily consumed by log management solutions',
      'Ensure high-value transactions have an audit trail',
      'Establish effective monitoring and alerting',
      'Establish incident response and recovery plan',
    ],
    preventionKo: [
      '모든 로그인, 접근 제어, 입력 검증 실패를 로깅하세요',
      '로그 관리 솔루션이 쉽게 처리할 수 있는 형식으로 로그를 생성하세요',
      '고가치 트랜잭션에 감사 추적을 확보하세요',
      '효과적인 모니터링 및 알림을 구축하세요',
      '인시던트 대응 및 복구 계획을 수립하세요',
    ],
  },
  {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    nameKo: '서버 사이드 요청 위조 (SSRF)',
    description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.',
    descriptionKo: '웹 앱이 사용자 제공 URL을 검증하지 않고 원격 리소스를 가져올 때 발생합니다.',
    prevalence: 'New category for 2021',
    cwes: ['CWE-918'],
    prevention: [
      'Sanitize and validate all client-supplied input data',
      'Enforce URL schema, port, and destination with allowlist',
      'Do not send raw responses to clients',
      'Disable HTTP redirections',
      'Use network segmentation to block SSRF impact',
    ],
    preventionKo: [
      '모든 클라이언트 제공 입력 데이터를 검증하세요',
      '허용 목록으로 URL 스키마, 포트, 대상을 제한하세요',
      '원시 응답을 클라이언트에 전송하지 마세요',
      'HTTP 리다이렉션을 비활성화하세요',
      '네트워크 분리로 SSRF 영향을 차단하세요',
    ],
  },
];

export function getOwaspResource(year: string = '2021'): string {
  if (year !== '2021') {
    return `⚠️ 현재 OWASP Top 10 2021만 지원합니다.`;
  }

  const lines: string[] = [];
  lines.push('# OWASP Top 10 - 2021');
  lines.push('');

  for (const item of OWASP_TOP10_2021) {
    lines.push(`## ${item.id} - ${item.nameKo} (${item.name})`);
    lines.push('');
    lines.push(item.descriptionKo);
    lines.push('');
    lines.push('### 예방 방법');
    for (const p of item.preventionKo) {
      lines.push(`- ${p}`);
    }
    lines.push('');
    lines.push(`관련 CWE: ${item.cwes.join(', ')}`);
    lines.push('');
    lines.push('---');
    lines.push('');
  }

  return lines.join('\n');
}
