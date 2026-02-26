export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type Language = 'javascript' | 'typescript' | 'python' | 'java' | 'php' | 'go' | 'ruby' | 'csharp' | 'unknown';
export type Context = 'frontend' | 'backend' | 'fullstack' | 'api' | 'config';

export interface CodeLocation {
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  filePath?: string;
}

export interface Remediation {
  description: string;
  descriptionKo: string;
  secureExample?: string;
  references: string[];
}

export interface RulePattern {
  regex: RegExp;
  /** If this pattern matches the same line, suppress the finding (reduces false positives) */
  negativeRegex?: RegExp;
  /** Multi-line pattern match */
  multiline?: boolean;
}

export interface SecurityRule {
  id: string;
  title: string;
  titleKo: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cweId: string;
  owaspCategory?: string;
  description: string;
  descriptionKo: string;
  patterns: RulePattern[];
  languages: Language[];
  frameworks?: string[];
  remediation: Remediation;
  tags: string[];
}

export interface Vulnerability {
  id: string;
  ruleId: string;
  title: string;
  titleKo: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cweId: string;
  owaspCategory?: string;
  location: CodeLocation;
  matchedCode: string;
  description: string;
  descriptionKo: string;
  attackScenario?: string;
  impact?: string;
  remediation: Remediation;
}

export interface ScanSummary {
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  riskScore: number;
}

export interface ScanResult {
  scanId: string;
  timestamp: string;
  targetType: 'code' | 'file' | 'project';
  language: Language;
  framework?: string;
  summary: ScanSummary;
  vulnerabilities: Vulnerability[];
  suggestions: string[];
}

export interface CodeUsageFinding {
  filePath?: string;
  line?: number;
  matchedCode: string;
  pattern: string;
  codeRemediation: string;
  codeRemediationKo: string;
  safeAlternative: string;
}

export interface DependencyVulnerability {
  packageName: string;
  installedVersion: string;
  vulnerableRange: string;
  patchedVersion?: string;
  severity: Severity;
  cveId?: string;
  cweId?: string;
  ghsaId?: string;
  osvId?: string;
  source: 'osv-realtime' | 'nvd' | 'local-db';
  cvssScore?: number;
  cvssVector?: string;
  cvssSeverity?: string;
  title: string;
  description: string;
  exploitAvailable: boolean;
  fixCommand?: string;
  references: string[];
  codeUsageFindings?: CodeUsageFinding[];
}

export interface DependencyScanResult {
  scanId: string;
  timestamp: string;
  manifest: string;
  totalDependencies: number;
  vulnerableCount: number;
  vulnerabilities: DependencyVulnerability[];
  recommendations: string[];
}

export interface ConfigAuditFinding {
  file: string;
  line?: number;
  key: string;
  severity: Severity;
  issue: string;
  issueKo: string;
  recommendation: string;
  recommendationKo: string;
}

