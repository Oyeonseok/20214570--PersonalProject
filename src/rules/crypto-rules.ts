import type { SecurityRule } from '../types/index.js';

export const cryptoRules: SecurityRule[] = [
  {
    id: 'SCG-CRY-RAND-001',
    title: 'Insecure Randomness (Math.random)',
    titleKo: '안전하지 않은 난수 생성 (Math.random)',
    severity: 'high',
    confidence: 'high',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-330',
    owaspCategory: 'A02',
    description: 'Math.random() is not cryptographically secure. Using it for security-sensitive operations is dangerous.',
    descriptionKo: 'Math.random()은 암호학적으로 안전하지 않습니다. 보안에 민감한 작업에 사용하면 위험합니다.',
    patterns: [
      {
        regex: /Math\.random\s*\(\s*\).*?(?:token|secret|key|password|session|csrf|nonce|salt|otp|code|id)/i,
      },
      {
        regex: /(?:token|secret|key|password|session|csrf|nonce|salt|otp|code)\s*[:=].*?Math\.random/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.',
      descriptionKo: '보안에 민감한 난수에는 crypto.randomBytes() 또는 crypto.randomUUID()를 사용하세요.',
      secureExample: `// ✅ Secure: Use crypto module
import { randomBytes, randomUUID } from 'crypto';
const token = randomBytes(32).toString('hex');
const id = randomUUID();`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
      ],
    },
    tags: ['random', 'cryptography', 'token'],
  },

  {
    id: 'SCG-CRY-ALGO-001',
    title: 'Weak Encryption Algorithm (DES/RC4)',
    titleKo: '취약한 암호화 알고리즘 (DES/RC4)',
    severity: 'high',
    confidence: 'high',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-327',
    owaspCategory: 'A02',
    description: 'Weak or deprecated encryption algorithms detected (DES, RC4, Blowfish).',
    descriptionKo: '취약하거나 더 이상 사용되지 않는 암호화 알고리즘이 감지되었습니다 (DES, RC4, Blowfish).',
    patterns: [
      {
        regex: /createCipher(?:iv)?\s*\(\s*['"](?:des|rc4|blowfish|des-ede|rc2)['"]/i,
      },
      {
        regex: /(?:DES|RC4|Blowfish|DESede).*?(?:encrypt|decrypt|cipher)/i,
      },
      {
        regex: /AES.*?ECB/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'csharp'],
    remediation: {
      description: 'Use AES-256-GCM or ChaCha20-Poly1305. Avoid ECB mode.',
      descriptionKo: 'AES-256-GCM 또는 ChaCha20-Poly1305를 사용하세요. ECB 모드를 피하세요.',
      secureExample: `// ✅ Secure: AES-256-GCM
import { createCipheriv, randomBytes } from 'crypto';
const key = randomBytes(32);
const iv = randomBytes(16);
const cipher = createCipheriv('aes-256-gcm', key, iv);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
      ],
    },
    tags: ['encryption', 'des', 'rc4', 'weak-crypto'],
  },

  {
    id: 'SCG-CRY-KEY-001',
    title: 'Hardcoded Encryption Key',
    titleKo: '하드코딩된 암호화 키',
    severity: 'critical',
    confidence: 'medium',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-321',
    owaspCategory: 'A02',
    description: 'Encryption key is hardcoded in source code instead of being managed securely.',
    descriptionKo: '암호화 키가 보안적으로 관리되지 않고 소스코드에 하드코딩되어 있습니다.',
    patterns: [
      {
        regex: /(?:createCipher|createDecipher|createCipheriv|createDecipheriv)\s*\([^,]+,\s*['"][^'"]{8,}['"]/i,
      },
      {
        regex: /(?:encryption[_.]?key|crypto[_.]?key|secret[_.]?key|aes[_.]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
        negativeRegex: /process\.env|os\.environ|getenv/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python'],
    remediation: {
      description: 'Store encryption keys in environment variables or a key management service (KMS).',
      descriptionKo: '암호화 키를 환경변수나 키 관리 서비스(KMS)에 저장하세요.',
      secureExample: `// ✅ Secure: Load key from environment
const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
const cipher = createCipheriv('aes-256-gcm', key, iv);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html',
      ],
    },
    tags: ['encryption-key', 'hardcoded', 'key-management'],
  },

  {
    id: 'SCG-CRY-TLS-001',
    title: 'TLS Certificate Verification Disabled',
    titleKo: 'TLS 인증서 검증 비활성화',
    severity: 'high',
    confidence: 'high',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-295',
    owaspCategory: 'A02',
    description: 'TLS certificate verification is disabled, enabling man-in-the-middle attacks.',
    descriptionKo: 'TLS 인증서 검증이 비활성화되어 중간자 공격(MITM)에 노출됩니다.',
    patterns: [
      {
        regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0['"]?/i,
      },
      {
        regex: /rejectUnauthorized\s*:\s*false/i,
      },
      {
        regex: /verify\s*[:=]\s*False.*?(?:requests|ssl)/i,
      },
      {
        regex: /VERIFY_NONE|SSL_VERIFY_NONE/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'csharp'],
    remediation: {
      description: 'Never disable TLS certificate verification in production. Use proper CA certificates.',
      descriptionKo: '프로덕션에서 TLS 인증서 검증을 절대 비활성화하지 마세요. 적절한 CA 인증서를 사용하세요.',
      secureExample: `// ✅ Secure: Keep TLS verification enabled (default)
const agent = new https.Agent({
  rejectUnauthorized: true,  // Default, but explicit is good
  ca: fs.readFileSync('/path/to/ca-cert.pem'),
});`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
      ],
    },
    tags: ['tls', 'ssl', 'certificate', 'mitm'],
  },

  {
    id: 'SCG-CRY-HASH-001',
    title: 'Insecure Hash for Integrity',
    titleKo: '무결성 검증에 취약한 해시 사용',
    severity: 'medium',
    confidence: 'medium',
    category: 'A02:2021-Cryptographic Failures',
    cweId: 'CWE-328',
    owaspCategory: 'A02',
    description: 'MD5 or SHA1 used for integrity checking, which are vulnerable to collision attacks.',
    descriptionKo: '충돌 공격에 취약한 MD5 또는 SHA1이 무결성 검증에 사용됩니다.',
    patterns: [
      {
        regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/i,
      },
      {
        regex: /hashlib\.(?:md5|sha1)\s*\(/i,
      },
      {
        regex: /MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1)['"]\s*\)/i,
      },
    ],
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'csharp'],
    remediation: {
      description: 'Use SHA-256 or SHA-3 for integrity verification.',
      descriptionKo: '무결성 검증에 SHA-256 또는 SHA-3을 사용하세요.',
      secureExample: `// ✅ Secure: Use SHA-256
import { createHash } from 'crypto';
const hash = createHash('sha256').update(data).digest('hex');`,
      references: ['https://cwe.mitre.org/data/definitions/328.html'],
    },
    tags: ['hash', 'md5', 'sha1', 'integrity'],
  },
];
