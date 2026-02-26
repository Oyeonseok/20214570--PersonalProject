import type { SecurityRule } from '../types/index.js';

export const xssRules: SecurityRule[] = [
  {
    id: 'SCG-XSS-DOM-001',
    title: 'DOM-based XSS via innerHTML',
    titleKo: 'innerHTML을 통한 DOM 기반 XSS',
    severity: 'high',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-79',
    owaspCategory: 'A03',
    description: 'Setting innerHTML with dynamic content can lead to DOM-based XSS.',
    descriptionKo: '동적 콘텐츠로 innerHTML을 설정하면 DOM 기반 XSS에 노출됩니다.',
    patterns: [
      {
        regex: /\.innerHTML\s*=\s*(?!['"`]\s*$)/,
        negativeRegex: /\.innerHTML\s*=\s*(?:['"]\s*['"]|['"]<(?:svg|i|span|img|br|hr|b|em|strong|icon)\b[^'"]*['"]|(?:DOMPurify\.sanitize|sanitize|sanitizeHtml|xss)\s*\()/i,
      },
      {
        regex: /\.innerHTML\s*\+=\s*/,
        negativeRegex: /\.innerHTML\s*\+=\s*(?:DOMPurify\.sanitize|sanitize|sanitizeHtml|xss)\s*\(/i,
      },
      {
        regex: /\.outerHTML\s*=\s*(?!['"`]\s*$)/,
        negativeRegex: /\.outerHTML\s*=\s*(?:['"]\s*['"]|(?:DOMPurify\.sanitize|sanitize)\s*\()/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Use textContent or innerText for text. Use DOM APIs for element creation.',
      descriptionKo: '텍스트는 textContent/innerText를 사용하세요. 엘리먼트 생성은 DOM API를 사용하세요.',
      secureExample: `// ✅ Secure: Use textContent for text
element.textContent = userInput;

// ✅ Secure: Use DOM API for elements
const el = document.createElement('div');
el.textContent = userInput;
parent.appendChild(el);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['xss', 'dom', 'innerHTML'],
  },

  {
    id: 'SCG-XSS-DOM-002',
    title: 'DOM-based XSS via document.write',
    titleKo: 'document.write를 통한 DOM 기반 XSS',
    severity: 'high',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-79',
    owaspCategory: 'A03',
    description: 'document.write() with dynamic content enables DOM-based XSS.',
    descriptionKo: '동적 콘텐츠와 함께 document.write()를 사용하면 DOM 기반 XSS에 노출됩니다.',
    patterns: [
      {
        regex: /document\.write\s*\(/,
      },
      {
        regex: /document\.writeln\s*\(/,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Avoid document.write(). Use modern DOM APIs instead.',
      descriptionKo: 'document.write()를 사용하지 마세요. 현대적인 DOM API를 사용하세요.',
      secureExample: `// ✅ Secure: Use modern DOM APIs
const el = document.createElement('script');
el.src = trustedUrl;
document.head.appendChild(el);`,
      references: ['https://cwe.mitre.org/data/definitions/79.html'],
    },
    tags: ['xss', 'dom', 'document-write'],
  },

  {
    id: 'SCG-XSS-REACT-001',
    title: 'XSS via dangerouslySetInnerHTML',
    titleKo: 'dangerouslySetInnerHTML을 통한 XSS',
    severity: 'high',
    confidence: 'high',
    category: 'A03:2021-Injection',
    cweId: 'CWE-79',
    owaspCategory: 'A03',
    description: 'dangerouslySetInnerHTML renders unescaped HTML, bypassing React XSS protections.',
    descriptionKo: 'dangerouslySetInnerHTML은 이스케이프되지 않은 HTML을 렌더링하여 React XSS 보호를 우회합니다.',
    patterns: [
      {
        regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
        negativeRegex: /DOMPurify\.sanitize|sanitizeHtml|xss\(|purify/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    frameworks: ['react', 'nextjs'],
    remediation: {
      description: 'Avoid dangerouslySetInnerHTML. If unavoidable, sanitize with DOMPurify.',
      descriptionKo: 'dangerouslySetInnerHTML을 피하세요. 불가피하면 DOMPurify로 새니타이즈하세요.',
      secureExample: `// ✅ Secure: Sanitize HTML before rendering
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userHtml) }} />`,
      references: [
        'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html',
      ],
    },
    tags: ['xss', 'react', 'dangerouslySetInnerHTML'],
  },

  {
    id: 'SCG-XSS-DOM-003',
    title: 'DOM XSS via jQuery HTML Manipulation',
    titleKo: 'jQuery HTML 조작을 통한 DOM XSS',
    severity: 'high',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-79',
    owaspCategory: 'A03',
    description: 'jQuery methods that insert HTML can lead to XSS when used with untrusted data.',
    descriptionKo: 'HTML을 삽입하는 jQuery 메서드를 신뢰할 수 없는 데이터와 사용하면 XSS에 노출됩니다.',
    patterns: [
      {
        regex: /\$\s*\(.*?\)\.(?:html|append|prepend|after|before|replaceWith)\s*\((?!['"`]\s*$)/,
      },
      {
        regex: /\$\s*\([^)]*(?:location|document\.URL|document\.referrer|window\.name)/,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Use .text() instead of .html() for user content. Sanitize HTML before insertion.',
      descriptionKo: '사용자 콘텐츠에는 .html() 대신 .text()를 사용하세요.',
      secureExample: `// ✅ Secure: Use .text() for user content
$('#name').text(userInput);`,
      references: ['https://cwe.mitre.org/data/definitions/79.html'],
    },
    tags: ['xss', 'jquery', 'dom'],
  },

  {
    id: 'SCG-XSS-DOM-004',
    title: 'XSS via location.hash / URL parameters',
    titleKo: 'location.hash / URL 파라미터를 통한 XSS',
    severity: 'medium',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-79',
    owaspCategory: 'A03',
    description: 'URL fragment or parameters used in DOM operations without sanitization.',
    descriptionKo: 'URL 프래그먼트나 파라미터가 새니타이즈 없이 DOM 조작에 사용됩니다.',
    patterns: [
      {
        regex: /(?:location\.hash|location\.search|location\.href|document\.URL|document\.referrer|window\.name)/,
        negativeRegex: /(?:encodeURI|escape|sanitize|DOMPurify)/i,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Sanitize all URL-derived data before DOM insertion. Use URL API for parsing.',
      descriptionKo: 'DOM 삽입 전 모든 URL 기반 데이터를 새니타이즈하세요.',
      secureExample: `// ✅ Secure: Use URL API and sanitize
const url = new URL(window.location.href);
const param = url.searchParams.get('name') ?? '';
element.textContent = param;  // textContent is safe`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
      ],
    },
    tags: ['xss', 'dom', 'url-based'],
  },

  {
    id: 'SCG-XSS-POSTMSG-001',
    title: 'Insecure postMessage Handler',
    titleKo: '안전하지 않은 postMessage 핸들러',
    severity: 'medium',
    confidence: 'medium',
    category: 'A03:2021-Injection',
    cweId: 'CWE-346',
    owaspCategory: 'A03',
    description: 'Message event handler does not verify origin, allowing cross-origin attacks.',
    descriptionKo: '메시지 이벤트 핸들러가 출처를 검증하지 않아 크로스 오리진 공격에 노출됩니다.',
    patterns: [
      {
        regex: /addEventListener\s*\(\s*['"]message['"]/,
        negativeRegex: /event\.origin\s*(?:===|!==|==|!=)|\.origin\s*(?:===|!==)/,
      },
      {
        regex: /onmessage\s*=/,
        negativeRegex: /event\.origin\s*(?:===|!==|==|!=)/,
      },
    ],
    languages: ['javascript', 'typescript'],
    remediation: {
      description: 'Always verify event.origin in postMessage handlers.',
      descriptionKo: 'postMessage 핸들러에서 항상 event.origin을 검증하세요.',
      secureExample: `// ✅ Secure: Verify origin
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted-site.com') return;
  // Process message
});`,
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns',
      ],
    },
    tags: ['xss', 'postMessage', 'cross-origin'],
  },
];
