import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { scanCode } from '../engine/scanner.js';
import { applySecureFixes } from '../engine/secure-fixer.js';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: '요청이 너무 많습니다. 잠시 후 다시 시도하세요.' },
});

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY ?? '';
const MODEL = process.env.MODEL ?? 'claude-sonnet-4-20250514';
const PORT = Number(process.env.PORT ?? 3000);

// Claude API 호출 → 코드 생성
async function callClaude(userMessage: string, history: ChatMessage[]): Promise<string> {
  if (!ANTHROPIC_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY가 설정되지 않았습니다. .env 파일에 추가하세요.');
  }

  const messages = [
    ...history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user' as const, content: userMessage },
  ];

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 8192,
      system: `당신은 웹 개발 전문가입니다. 사용자가 요청하는 웹 페이지나 기능을 구현해주세요. 
반드시 완성된 코드를 제공하세요. HTML 페이지를 요청하면 <!DOCTYPE html>부터 </html>까지 전체 코드를 작성하세요.
코드는 반드시 \`\`\` 코드블록 안에 작성하세요.`,
      messages,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Claude API 오류 (${res.status}): ${err}`);
  }

  const data = (await res.json()) as { content: Array<{ type: string; text?: string }> };
  return data.content
    .filter((b) => b.type === 'text' && b.text)
    .map((b) => b.text!)
    .join('\n');
}

// 응답에서 코드 블록 추출
function extractCodeBlocks(text: string): Array<{ lang: string; code: string }> {
  const blocks: Array<{ lang: string; code: string }> = [];
  const regex = /```(\w*)\n([\s\S]*?)```/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    blocks.push({ lang: match[1] || 'text', code: match[2].trim() });
  }
  return blocks;
}

// 코드에 시큐어코딩 적용
function applySecurityToCode(code: string, lang: string) {
  const scanResult = scanCode(code, { severityThreshold: 'info' });
  const fixResult = applySecureFixes(code, scanResult.vulnerabilities);
  return { scanResult, fixResult };
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

// ─── API 엔드포인트 ───

app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const { message, history } = req.body as {
      message: string;
      history?: ChatMessage[];
    };

    if (!message) {
      res.status(400).json({ error: '메시지가 비어있습니다.' });
      return;
    }

    // 1단계: Claude에게 코드 생성 요청
    const claudeResponse = await callClaude(message, history ?? []);

    // 2단계: 코드 블록 추출
    const codeBlocks = extractCodeBlocks(claudeResponse);

    if (codeBlocks.length === 0) {
      res.json({
        response: claudeResponse,
        secured: false,
        securityReport: null,
      });
      return;
    }

    // 3단계: 각 코드 블록에 시큐어코딩 적용
    const securedBlocks: Array<{
      lang: string;
      original: string;
      secured: string;
      report: {
        totalIssues: number;
        autoFixed: number;
        manualNeeded: number;
        headersAdded: number;
        appliedFixes: Array<{ severity: string; description: string; line: number }>;
        manualFixes: Array<{ severity: string; description: string; suggestion: string; line: number }>;
        injectedHeaders: string[];
      };
    }> = [];

    let finalResponse = claudeResponse;

    for (const block of codeBlocks) {
      const { scanResult, fixResult } = applySecurityToCode(block.code, block.lang);

      const report = {
        totalIssues: scanResult.summary.totalIssues,
        autoFixed: fixResult.appliedFixes.length,
        manualNeeded: fixResult.manualFixes.length,
        headersAdded: fixResult.injectedHeaders.length,
        appliedFixes: fixResult.appliedFixes.map((f) => ({
          severity: f.severity,
          description: f.description,
          line: f.line,
        })),
        manualFixes: fixResult.manualFixes.map((f) => ({
          severity: f.severity,
          description: f.description,
          suggestion: f.suggestion,
          line: f.line,
        })),
        injectedHeaders: fixResult.injectedHeaders,
      };

      securedBlocks.push({
        lang: block.lang,
        original: block.code,
        secured: fixResult.fixedCode,
        report,
      });

      // 원본 코드 블록을 시큐어 코드로 교체
      finalResponse = finalResponse.replace(
        '```' + block.lang + '\n' + block.code + '\n```',
        '```' + block.lang + '\n' + fixResult.fixedCode + '\n```'
      );
    }

    res.json({
      response: finalResponse,
      secured: true,
      securityReport: {
        blocks: securedBlocks,
      },
    });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : '알 수 없는 오류';
    console.error('[Error]', errorMessage);
    res.status(500).json({ error: errorMessage });
  }
});

// 상태 확인
app.get('/api/status', (_req, res) => {
  res.json({
    ok: true,
    apiKeySet: !!ANTHROPIC_API_KEY,
    model: MODEL,
  });
});

export { app };

const isDirectRun = process.argv[1]?.includes('server');
if (isDirectRun) {
  app.listen(PORT, () => {
    console.log(`\n🛡️  SecureCode Guardian 웹 채팅`);
    console.log(`   http://localhost:${PORT}`);
    console.log(`   API Key: ${ANTHROPIC_API_KEY ? '✅ 설정됨' : '❌ 미설정 (.env에 ANTHROPIC_API_KEY 추가)'}`);
    console.log(`   Model: ${MODEL}\n`);
  });
}
