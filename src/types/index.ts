export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type Language = 'javascript' | 'typescript' | 'python' | 'java' | 'unknown';
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

export interface SecureCodeResult {
  original?: string;
  secure: string;
  language: Language;
  explanation: string;
  explanationKo: string;
  appliedPatterns: string[];
  securityFeatures: string[];
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

export interface ConfigAuditResult {
  scanId: string;
  timestamp: string;
  file: string;
  findings: ConfigAuditFinding[];
  summary: ScanSummary;
}

export interface GuardianConfig {
  analysisMode: 'lite' | 'standard' | 'deep';
  severityThreshold: Severity;
  enabledRuleSets: string[];
  excludeRules: string[];
  maxFileSize: number;
  excludePaths: string[];
}

export const DEFAULT_CONFIG: GuardianConfig = {
  analysisMode: 'lite',
  severityThreshold: 'low',
  enabledRuleSets: ['owasp', 'cwe-top25'],
  excludeRules: [],
  maxFileSize: 500 * 1024,
  excludePaths: ['node_modules', '.git', 'dist', 'build', '__pycache__', '.next'],
};
