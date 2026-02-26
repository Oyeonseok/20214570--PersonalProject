import { describe, it, expect } from 'vitest';
import {
  detectLanguageFromExtension,
  detectLanguageFromCode,
  detectLanguage,
} from '../../../src/utils/language-detector.js';

describe('detectLanguageFromExtension', () => {
  it('detects TypeScript', () => {
    expect(detectLanguageFromExtension('app.ts')).toBe('typescript');
    expect(detectLanguageFromExtension('component.tsx')).toBe('typescript');
    expect(detectLanguageFromExtension('/src/index.mts')).toBe('typescript');
  });

  it('detects JavaScript', () => {
    expect(detectLanguageFromExtension('app.js')).toBe('javascript');
    expect(detectLanguageFromExtension('component.jsx')).toBe('javascript');
    expect(detectLanguageFromExtension('config.mjs')).toBe('javascript');
    expect(detectLanguageFromExtension('config.cjs')).toBe('javascript');
  });

  it('detects Python', () => {
    expect(detectLanguageFromExtension('main.py')).toBe('python');
    expect(detectLanguageFromExtension('script.pyw')).toBe('python');
  });

  it('detects Java', () => {
    expect(detectLanguageFromExtension('Main.java')).toBe('java');
  });

  it('returns unknown for unsupported extensions', () => {
    expect(detectLanguageFromExtension('file.rb')).toBe('unknown');
    expect(detectLanguageFromExtension('file.go')).toBe('unknown');
    expect(detectLanguageFromExtension('file')).toBe('unknown');
  });
});

describe('detectLanguageFromCode', () => {
  it('detects TypeScript from type annotations', () => {
    const code = 'const x: string = "hello";\ninterface User { name: string; }';
    expect(detectLanguageFromCode(code)).toBe('typescript');
  });

  it('detects JavaScript from common patterns', () => {
    const code = 'const x = require("fs");\nmodule.exports = {};\nlet y = 5;';
    expect(detectLanguageFromCode(code)).toBe('javascript');
  });

  it('detects Python', () => {
    const code = 'def main():\n    import os\n    print("hello")\n    self.name = "test"';
    expect(detectLanguageFromCode(code)).toBe('python');
  });

  it('detects Java', () => {
    const code = 'public class Main {\n    public static void main(String[] args) {\n        System.out.println("hello");\n    }\n}';
    expect(detectLanguageFromCode(code)).toBe('java');
  });

  it('returns unknown for ambiguous code', () => {
    const code = '// just a comment';
    expect(detectLanguageFromCode(code)).toBe('unknown');
  });
});

describe('detectLanguage', () => {
  it('prefers file extension over code analysis', () => {
    const tsCode = 'def main():\n    print("python")';
    expect(detectLanguage(tsCode, 'app.ts')).toBe('typescript');
  });

  it('prefers hint over file extension', () => {
    expect(detectLanguage('', 'app.ts', 'python')).toBe('python');
  });

  it('falls back to code detection when no extension', () => {
    const pyCode = 'def greet(name):\n    print(f"Hello {name}")';
    expect(detectLanguage(pyCode)).toBe('python');
  });
});
