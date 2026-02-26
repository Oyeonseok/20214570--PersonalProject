const OSV_API_BASE = 'https://api.osv.dev/v1';
const DEFAULT_TIMEOUT = 5000;
const CACHE_TTL = 30 * 60 * 1000;

export interface OsvPackageQuery {
  name: string;
  ecosystem: 'npm' | 'PyPI';
  version?: string;
}

export interface OsvVulnSummary {
  id: string;
  modified: string;
}

export interface OsvBatchResult {
  results: Array<{ vulns?: OsvVulnSummary[] }>;
}

export interface OsvAffectedRange {
  type: string;
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

export interface OsvAffectedPackage {
  package: { name: string; ecosystem: string; purl?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
}

export interface OsvReference {
  type: string;
  url: string;
}

export interface OsvVulnDetail {
  id: string;
  summary?: string;
  details?: string;
  modified: string;
  published?: string;
  aliases?: string[];
  related?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: OsvAffectedPackage[];
  references?: OsvReference[];
  database_specific?: Record<string, unknown>;
}

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry<unknown>>();

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

async function fetchWithTimeout(url: string, options: RequestInit, timeout = DEFAULT_TIMEOUT): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

export async function queryBatch(packages: OsvPackageQuery[]): Promise<OsvBatchResult> {
  if (packages.length === 0) return { results: [] };

  const cacheKey = `batch:${packages.map((p) => `${p.ecosystem}/${p.name}@${p.version ?? '*'}`).join(',')}`;
  const cached = getCached<OsvBatchResult>(cacheKey);
  if (cached) return cached;

  const queries = packages.map((pkg) => ({
    package: { name: pkg.name, ecosystem: pkg.ecosystem },
    ...(pkg.version ? { version: pkg.version } : {}),
  }));

  const res = await fetchWithTimeout(`${OSV_API_BASE}/querybatch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries }),
  });

  if (!res.ok) {
    throw new Error(`OSV API error: ${res.status} ${res.statusText}`);
  }

  const data = (await res.json()) as OsvBatchResult;
  setCache(cacheKey, data);
  return data;
}

export async function getVulnDetail(vulnId: string): Promise<OsvVulnDetail> {
  const cacheKey = `vuln:${vulnId}`;
  const cached = getCached<OsvVulnDetail>(cacheKey);
  if (cached) return cached;

  const res = await fetchWithTimeout(`${OSV_API_BASE}/vulns/${encodeURIComponent(vulnId)}`, {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });

  if (!res.ok) {
    throw new Error(`OSV API error for ${vulnId}: ${res.status} ${res.statusText}`);
  }

  const data = (await res.json()) as OsvVulnDetail;
  setCache(cacheKey, data);
  return data;
}

export function extractCveId(vuln: OsvVulnDetail): string | undefined {
  if (vuln.id.startsWith('CVE-')) return vuln.id;
  return vuln.aliases?.find((a) => a.startsWith('CVE-'));
}

export function extractGhsaId(vuln: OsvVulnDetail): string | undefined {
  if (vuln.id.startsWith('GHSA-')) return vuln.id;
  return vuln.aliases?.find((a) => a.startsWith('GHSA-'));
}

export function extractFixedVersion(vuln: OsvVulnDetail, packageName: string): string | undefined {
  const affected = vuln.affected?.find((a) => a.package.name === packageName);
  if (!affected?.ranges) return undefined;

  for (const range of affected.ranges) {
    for (const event of range.events) {
      if (event.fixed) return event.fixed;
    }
  }
  return undefined;
}

