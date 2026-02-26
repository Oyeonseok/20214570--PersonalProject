const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const DEFAULT_TIMEOUT = 10000;
const CACHE_TTL = 60 * 60 * 1000;

const RATE_LIMIT_WITH_KEY = { requests: 50, windowMs: 30000 };
const RATE_LIMIT_NO_KEY = { requests: 5, windowMs: 30000 };

export interface CvssData {
  baseScore: number;
  baseSeverity: string;
  vectorString: string;
  version: string;
}

export interface NvdCveDetail {
  cveId: string;
  description: string;
  cvss?: CvssData;
  cweIds: string[];
  references: Array<{ url: string; source: string }>;
  published?: string;
  lastModified?: string;
}

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry<unknown>>();
const requestTimestamps: number[] = [];

function getCached<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.data as T;
}

function setCache<T>(key: string, data: T): void {
  cache.set(key, { data, expiresAt: Date.now() + CACHE_TTL });
}

function getApiKey(): string | undefined {
  return process.env.NVD_API_KEY || undefined;
}

async function waitForRateLimit(): Promise<void> {
  const apiKey = getApiKey();
  const limit = apiKey ? RATE_LIMIT_WITH_KEY : RATE_LIMIT_NO_KEY;
  const now = Date.now();
  const windowStart = now - limit.windowMs;

  while (requestTimestamps.length > 0 && requestTimestamps[0] < windowStart) {
    requestTimestamps.shift();
  }

  if (requestTimestamps.length >= limit.requests) {
    const waitUntil = requestTimestamps[0] + limit.windowMs;
    const delay = waitUntil - now + 100;
    if (delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  requestTimestamps.push(Date.now());
}

async function fetchWithTimeout(url: string, options: RequestInit, timeout = DEFAULT_TIMEOUT): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function getCveDetail(cveId: string): Promise<NvdCveDetail | null> {
  const cacheKey = `nvd:${cveId}`;
  const cached = getCached<NvdCveDetail>(cacheKey);
  if (cached) return cached;

  await waitForRateLimit();

  const headers: Record<string, string> = { Accept: 'application/json' };
  const apiKey = getApiKey();
  if (apiKey) {
    headers['apiKey'] = apiKey;
  }

  const res = await fetchWithTimeout(
    `${NVD_API_BASE}?cveId=${encodeURIComponent(cveId)}`,
    { method: 'GET', headers },
  );

  if (!res.ok) {
    if (res.status === 404) return null;
    throw new Error(`NVD API error: ${res.status} ${res.statusText}`);
  }

  const body = await res.json() as { vulnerabilities?: Array<{ cve: NvdRawCve }> };
  const vulns = body.vulnerabilities;
  if (!vulns || vulns.length === 0) return null;

  const raw = vulns[0].cve;
  const detail = parseNvdCve(raw);
  setCache(cacheKey, detail);
  return detail;
}

interface NvdRawCve {
  id: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV2?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
  };
  weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
  references?: Array<{ url: string; source?: string }>;
  published?: string;
  lastModified?: string;
}

function parseNvdCve(raw: NvdRawCve): NvdCveDetail {
  const description =
    raw.descriptions?.find((d) => d.lang === 'en')?.value ??
    raw.descriptions?.[0]?.value ??
    '';

  const cvss = extractCvss(raw.metrics);
  const cweIds = extractCweIds(raw.weaknesses);
  const references = (raw.references ?? []).map((r) => ({
    url: r.url,
    source: r.source ?? 'unknown',
  }));

  return {
    cveId: raw.id,
    description,
    cvss: cvss ?? undefined,
    cweIds,
    references,
    published: raw.published,
    lastModified: raw.lastModified,
  };
}

function extractCvss(metrics?: NvdRawCve['metrics']): CvssData | null {
  if (!metrics) return null;

  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  if (v31) {
    return {
      baseScore: v31.baseScore,
      baseSeverity: v31.baseSeverity,
      vectorString: v31.vectorString,
      version: '3.1',
    };
  }

  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  if (v30) {
    return {
      baseScore: v30.baseScore,
      baseSeverity: v30.baseSeverity,
      vectorString: v30.vectorString,
      version: '3.0',
    };
  }

  const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
  if (v2) {
    return {
      baseScore: v2.baseScore,
      baseSeverity: v2.baseSeverity ?? 'MEDIUM',
      vectorString: v2.vectorString,
      version: '2.0',
    };
  }

  return null;
}

function extractCweIds(weaknesses?: NvdRawCve['weaknesses']): string[] {
  if (!weaknesses) return [];
  const ids: string[] = [];
  for (const w of weaknesses) {
    for (const d of w.description) {
      if (d.value.startsWith('CWE-') && d.value !== 'CWE-noinfo') {
        ids.push(d.value);
      }
    }
  }
  return [...new Set(ids)];
}

export function cvssToSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
