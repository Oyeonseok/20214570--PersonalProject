export interface CweEntry {
  id: string;
  name: string;
  nameKo: string;
  description: string;
  descriptionKo: string;
  severity: string;
  url: string;
}

export const CWE_DATABASE: CweEntry[] = [
  { id: 'CWE-22', name: 'Path Traversal', nameKo: '경로 탐색', description: 'Improper Limitation of a Pathname to a Restricted Directory', descriptionKo: '제한된 디렉토리에 대한 경로명 제한 미흡', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/22.html' },
  { id: 'CWE-78', name: 'OS Command Injection', nameKo: 'OS 명령어 인젝션', description: 'Improper Neutralization of Special Elements used in an OS Command', descriptionKo: 'OS 명령에 사용되는 특수 문자의 부적절한 무효화', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/78.html' },
  { id: 'CWE-79', name: 'Cross-site Scripting (XSS)', nameKo: '크로스 사이트 스크립팅', description: 'Improper Neutralization of Input During Web Page Generation', descriptionKo: '웹 페이지 생성 시 입력의 부적절한 무효화', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/79.html' },
  { id: 'CWE-89', name: 'SQL Injection', nameKo: 'SQL 인젝션', description: 'Improper Neutralization of Special Elements used in an SQL Command', descriptionKo: 'SQL 명령에 사용되는 특수 문자의 부적절한 무효화', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/89.html' },
  { id: 'CWE-94', name: 'Code Injection', nameKo: '코드 인젝션', description: 'Improper Control of Generation of Code', descriptionKo: '코드 생성의 부적절한 제어', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/94.html' },
  { id: 'CWE-113', name: 'HTTP Response Splitting', nameKo: 'HTTP 응답 분할', description: 'Improper Neutralization of CRLF Sequences in HTTP Headers', descriptionKo: 'HTTP 헤더의 CRLF 시퀀스 무효화 미흡', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/113.html' },
  { id: 'CWE-117', name: 'Log Injection', nameKo: '로그 인젝션', description: 'Improper Output Neutralization for Logs', descriptionKo: '로그를 위한 출력 무효화 미흡', severity: 'medium', url: 'https://cwe.mitre.org/data/definitions/117.html' },
  { id: 'CWE-209', name: 'Error Information Exposure', nameKo: '에러 정보 노출', description: 'Generation of Error Message Containing Sensitive Information', descriptionKo: '민감 정보를 포함하는 에러 메시지 생성', severity: 'medium', url: 'https://cwe.mitre.org/data/definitions/209.html' },
  { id: 'CWE-295', name: 'Improper Certificate Validation', nameKo: '부적절한 인증서 검증', description: 'Improper Validation of Certificate', descriptionKo: '인증서의 부적절한 검증', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/295.html' },
  { id: 'CWE-321', name: 'Hard-coded Cryptographic Key', nameKo: '하드코딩된 암호화 키', description: 'Use of Hard-coded Cryptographic Key', descriptionKo: '하드코딩된 암호화 키 사용', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/321.html' },
  { id: 'CWE-327', name: 'Broken Crypto Algorithm', nameKo: '취약한 암호 알고리즘', description: 'Use of a Broken or Risky Cryptographic Algorithm', descriptionKo: '깨지거나 위험한 암호 알고리즘 사용', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/327.html' },
  { id: 'CWE-328', name: 'Reversible One-Way Hash', nameKo: '역전 가능한 단방향 해시', description: 'Use of Weak Hash', descriptionKo: '취약한 해시 사용', severity: 'medium', url: 'https://cwe.mitre.org/data/definitions/328.html' },
  { id: 'CWE-330', name: 'Insufficient Randomness', nameKo: '불충분한 난수성', description: 'Use of Insufficiently Random Values', descriptionKo: '불충분한 난수 값 사용', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/330.html' },
  { id: 'CWE-345', name: 'Insufficient Verification', nameKo: '불충분한 검증', description: 'Insufficient Verification of Data Authenticity', descriptionKo: '데이터 진정성의 불충분한 검증', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/345.html' },
  { id: 'CWE-346', name: 'Origin Validation Error', nameKo: '출처 검증 오류', description: 'Origin Validation Error', descriptionKo: '출처 검증 오류', severity: 'medium', url: 'https://cwe.mitre.org/data/definitions/346.html' },
  { id: 'CWE-352', name: 'Cross-Site Request Forgery', nameKo: 'CSRF', description: 'Cross-Site Request Forgery (CSRF)', descriptionKo: '크로스 사이트 요청 위조', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/352.html' },
  { id: 'CWE-384', name: 'Session Fixation', nameKo: '세션 고정', description: 'Session Fixation', descriptionKo: '세션 고정 공격', severity: 'medium', url: 'https://cwe.mitre.org/data/definitions/384.html' },
  { id: 'CWE-502', name: 'Deserialization of Untrusted Data', nameKo: '신뢰할 수 없는 데이터 역직렬화', description: 'Deserialization of Untrusted Data', descriptionKo: '신뢰할 수 없는 데이터의 역직렬화', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/502.html' },
  { id: 'CWE-614', name: 'Sensitive Cookie Without Secure Flag', nameKo: 'Secure 플래그 없는 민감 쿠키', description: 'Sensitive Cookie in HTTPS Session Without Secure Attribute', descriptionKo: 'Secure 속성 없이 HTTPS 세션의 민감 쿠키', severity: 'medium', url: 'https://cwe.mitre.org/data/definitions/614.html' },
  { id: 'CWE-798', name: 'Hard-coded Credentials', nameKo: '하드코딩된 자격증명', description: 'Use of Hard-coded Credentials', descriptionKo: '하드코딩된 자격증명 사용', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/798.html' },
  { id: 'CWE-918', name: 'Server-Side Request Forgery', nameKo: '서버 사이드 요청 위조', description: 'Server-Side Request Forgery (SSRF)', descriptionKo: '서버 측 요청 위조', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/918.html' },
  { id: 'CWE-942', name: 'Permissive CORS Policy', nameKo: '허용적인 CORS 정책', description: 'Overly Permissive Cross-domain Whitelist', descriptionKo: '지나치게 허용적인 크로스 도메인 화이트리스트', severity: 'high', url: 'https://cwe.mitre.org/data/definitions/942.html' },
  { id: 'CWE-943', name: 'NoSQL Injection', nameKo: 'NoSQL 인젝션', description: 'Improper Neutralization of Special Elements in Data Query Logic', descriptionKo: '데이터 쿼리 로직의 특수 요소 무효화 미흡', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/943.html' },
  { id: 'CWE-1336', name: 'Template Injection', nameKo: '템플릿 인젝션', description: 'Improper Neutralization of Special Elements Used in a Template Engine', descriptionKo: '템플릿 엔진에 사용되는 특수 요소 무효화 미흡', severity: 'critical', url: 'https://cwe.mitre.org/data/definitions/1336.html' },
];

export function getCweResource(cweId?: string): string {
  if (cweId) {
    const entry = CWE_DATABASE.find((e) => e.id === cweId || e.id === `CWE-${cweId}`);
    if (!entry) return `⚠️ CWE ID를 찾을 수 없습니다: ${cweId}`;

    return [
      `# ${entry.id}: ${entry.nameKo} (${entry.name})`,
      '',
      entry.descriptionKo,
      '',
      `심각도: ${entry.severity}`,
      `참조: ${entry.url}`,
    ].join('\n');
  }

  const lines = ['# CWE 취약점 데이터베이스', '', '| CWE ID | 이름 | 심각도 |', '|---|---|---|'];
  for (const e of CWE_DATABASE) {
    lines.push(`| ${e.id} | ${e.nameKo} | ${e.severity} |`);
  }
  return lines.join('\n');
}
