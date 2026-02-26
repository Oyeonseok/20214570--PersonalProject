import type { Language } from '../types/index.js';

const EXTENSION_MAP: Record<string, Language> = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.py': 'python',
  '.pyw': 'python',
  '.java': 'java',
};

const LANGUAGE_INDICATORS: Record<Language, RegExp[]> = {
  typescript: [
    /:\s*(string|number|boolean|void|any|never|unknown)\b/,
    /interface\s+\w+/,
    /type\s+\w+\s*=/,
    /<\w+(\s*,\s*\w+)*>/,
    /as\s+(string|number|boolean|any)/,
  ],
  javascript: [
    /\bconst\s+\w+\s*=/,
    /\blet\s+\w+\s*=/,
    /\bfunction\s+\w+\s*\(/,
    /=>\s*\{/,
    /require\s*\(/,
    /module\.exports/,
  ],
  python: [
    /\bdef\s+\w+\s*\(/,
    /\bimport\s+\w+/,
    /\bfrom\s+\w+\s+import/,
    /\bclass\s+\w+.*:/,
    /\bself\./,
    /\bprint\s*\(/,
  ],
  java: [
    /\bpublic\s+(class|interface|enum)/,
    /\bprivate\s+(static\s+)?\w+/,
    /\bSystem\.out\.print/,
    /\bimport\s+java\./,
    /\bextends\s+\w+/,
    /@Override/,
  ],
  unknown: [],
};

export function detectLanguageFromExtension(filePath: string): Language {
  const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();
  return EXTENSION_MAP[ext] ?? 'unknown';
}

export function detectLanguageFromCode(code: string): Language {
  const scores: Record<Language, number> = {
    typescript: 0,
    javascript: 0,
    python: 0,
    java: 0,
    unknown: 0,
  };

  for (const [lang, patterns] of Object.entries(LANGUAGE_INDICATORS)) {
    for (const pattern of patterns) {
      if (pattern.test(code)) {
        scores[lang as Language] += 1;
      }
    }
  }

  if (scores.typescript > 0 && scores.typescript >= scores.javascript) {
    return 'typescript';
  }

  let bestLang: Language = 'unknown';
  let bestScore = 0;
  for (const [lang, score] of Object.entries(scores)) {
    if (score > bestScore) {
      bestScore = score;
      bestLang = lang as Language;
    }
  }

  return bestScore > 0 ? bestLang : 'unknown';
}

export function detectLanguage(code: string, filePath?: string, hint?: string): Language {
  if (hint && hint in EXTENSION_MAP) {
    return hint as Language;
  }
  if (hint) {
    const mapped = Object.entries(EXTENSION_MAP).find(([, lang]) => lang === hint);
    if (mapped) return mapped[1];
  }
  if (filePath) {
    const fromExt = detectLanguageFromExtension(filePath);
    if (fromExt !== 'unknown') return fromExt;
  }
  return detectLanguageFromCode(code);
}
