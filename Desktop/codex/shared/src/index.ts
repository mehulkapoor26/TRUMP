export interface HealthResponse {
  status: 'ok';
  service: 'traceguard-api';
  timestamp: string;
  uptime: number;
}

export type Ecosystem = 'npm' | 'PyPI' | 'Maven';
export interface ScanFile { path: string; kind: 'manifest' | 'lockfile' | 'source'; bytes: number; ecosystem?: Ecosystem; sha256?: string }
export interface InventoryCounts { projectModules: number; uniquePackages: number; uniquePackageVersions: number; dependencyInstances: number; directDependencies: number; transitiveOnlyDependencies: number; unknownRelationships: number; dependencyEdges: number; unresolvedDeclarations: number }
export interface ProjectCoverage { path: string; manager: string; status: 'analyzed' | 'partial' | 'unknown' | 'unsupported' | 'failed'; reasons: string[] }
export interface ScanEvidence { scannerVersion: string; archiveSha256: string; repositoryUrl?: string; commitSha?: string; revisionStatus: 'pinned' | 'unknown'; inventorySha256: string; languages: string[]; projects: ProjectCoverage[]; metadataHashes: { path: string; sha256: string }[] }
export interface ScanResult {
  id: string;
  status: 'completed';
  createdAt: string;
  source: string;
  files: ScanFile[];
  graph?: DependencyGraph;
  sbom?: CycloneDxBom;
  sourceFiles?: SourceFileInfo[];
  ecosystems?: Ecosystem[];
  counts?: InventoryCounts;
  evidence?: ScanEvidence;
  analysisStatus?: ProjectCoverage['status'];
}

export type DependencyKind = 'runtime' | 'dev' | 'optional' | 'peer';
export interface DependencyNode {
  /** Absent in legacy npm records. */
  ecosystem?: Ecosystem;
  advisoryEligible?: boolean;
  versionEvidence?: 'lockfile' | 'exact-pin' | 'manifest-exact';
  projectPath?: string;
  sourceFile?: string;
  declaredConstraints?: string[];
  parentIds?: string[];
  purl?: string;
  resolutionConfidence?: 'recorded-lock' | 'declared-exact' | 'unresolved';
  limitations?: string[];
  id: string;
  name: string;
  version?: string;
  installPath: string;
  project: string;
  isProject: boolean;
  direct: boolean;
  transitive: boolean;
  integrity?: string;
  resolved?: string;
}
export interface DependencyEdge {
  from: string;
  to: string;
  name: string;
  requested: string;
  kind: DependencyKind;
  /** True only when peerDependenciesMeta marks this peer as optional. */
  optionalPeer?: boolean;
}
export interface UnresolvedDependency {
  from: string;
  name: string;
  requested: string;
  kind: DependencyKind;
  /** True only when peerDependenciesMeta marks this peer as optional. */
  optionalPeer?: boolean;
}
export interface DependencyGraph {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  roots: string[];
  unresolved: UnresolvedDependency[];
  warnings: string[];
}

export interface SbomComponent {
  type: 'application' | 'library';
  'bom-ref': string;
  name: string;
  version?: string;
  purl?: string;
  properties?: { name: string; value: string }[];
}
export interface CycloneDxBom {
  $schema: string;
  bomFormat: 'CycloneDX';
  specVersion: '1.6';
  serialNumber: string;
  version: number;
  metadata: { timestamp: string; component: SbomComponent; properties: { name: string; value: string }[] };
  components: SbomComponent[];
  dependencies: { ref: string; dependsOn: string[] }[];
  compositions: { aggregate: 'complete' | 'incomplete'; assemblies: string[] }[];
}

export interface AdvisoryCheck {
  nodeId: string;
  status: 'matched' | 'no-known' | 'unknown';
  complete: boolean;
  advisoryIds: string[];
}
export interface VulnerabilityReport {
  source: 'OSV';
  checkedAt: string;
  status: 'complete' | 'partial' | 'unavailable';
  checks: AdvisoryCheck[];
  warnings: string[];
  /** Keys are JSON.stringify([advisory ID, npm package name]). Details can be unavailable. */
  advisories?: Record<string, AdvisoryDetail>;
  scanId?: string;
  inventorySha256?: string;
  snapshotId?: string;
  evidence?: { requests: { queries: unknown[]; results?: unknown[]; error?: string; checkedAt: string }[]; details?: { url: string; checkedAt: string; data?: unknown; error?: string }[] };
  counts?: { affectedInstances: number; uniqueAdvisoryIds: number; uniqueIssuesByAliases: number; unknownInstances: number };
}

export interface SourceFileInfo { path: string; bytes: number; lines: number }
export interface SourceSnapshot {
  files: { path: string; content: string }[];
  skipped: { path: string; reason: string }[];
}
export interface ReachabilityRequest {
  entrypoints: { file: string; symbol: string }[];
  target: { packageNodeId: string; exportName: string; subpath?: string; advisoryId?: string };
}
export interface SourceEvidence {
  file: string; line: number; column: number; snippet: string;
  kind: 'entry' | 'import' | 'call' | 'target' | 'gap';
  from: string; to: string;
}
export interface ReachabilityReport {
  status: 'REACHABLE' | 'NOT REACHABLE' | 'UNKNOWN';
  reason: string;
  target: ReachabilityRequest['target'];
  mapping: 'user-declared export; not independently verified' | 'Python analysis unsupported' | 'Java analysis unsupported';
  coverage: {
    entrypoints: ReachabilityRequest['entrypoints'];
    analyzedFiles: string[];
    sourceFilesAvailable: number;
    skippedSources: SourceSnapshot['skipped'];
    functionsVisited: number;
    callsExamined: number;
    completeForDeclaredEntrypoints: boolean;
    boundary: string;
  };
  evidence: SourceEvidence[];
  gaps: { reason: string; evidence?: SourceEvidence }[];
  limitations: string[];
}


export interface ScanSummary {
  id: string; source: string; createdAt: string; status: 'completed';
  packages: number; relationships: number; warnings: number; sourceFiles: number;
}

export interface AdvisoryDetail {
  id: string; source: string; verification: 'verified' | 'unavailable' | 'withdrawn' | 'package-mismatch';
  summary: string; description: string; aliases: string[]; modified?: string;
  severity: { type: string; score: string }[];
  severityLabel?: string;
  fixedVersions: string[];
  references: string[];
  affectedVersions?: string[];
}
export interface SecurityFinding {
  id: string;
  package: DependencyNode;
  whatIsWrong: string;
  whyItMatters: string;
  advisories: AdvisoryDetail[];
  dependencyImpact: { parentCount: number; parents: { id: string; name: string; version?: string; installPath: string }[]; rootPaths: string[][]; truncated: boolean };
  reachability: { status: ReachabilityReport['status'] | 'NOT ANALYZED'; report?: ReachabilityReport };
  exploitability: 'NOT ASSESSED';
}
export interface ReportContext {
  advisorySnapshotId?: string;
  inventoryCounts?: InventoryCounts;
  scanEvidence?: ScanEvidence;
  comparison?: ScanComparison;
  schemaVersion: '1.0'; bundleId: string; generatedAt: string;
  scan: { id: string; source: string; createdAt: string; inventorySha256: string };
  coverage: { status: VulnerabilityReport['status']; checkedAt: string; packageInstances: number; matched: number; noKnownMatch: number; unknown: number; findingsIncluded: number; findingsOmitted: number };
  limitations: string[];
}
export interface SecurityFindingsReport extends ReportContext {
  reportType: 'security-findings'; title: 'Security Findings';
  findings: SecurityFinding[];
  inventoryWarnings: string[];
  packageRisk?: PackageRiskReport;
}
export interface RemediationAction {
  findingId: string; packageNodeId: string; packageName: string; installedVersion?: string;
  status: 'VERIFIED CANDIDATE' | 'MANUAL REVIEW';
  suggestedVersion?: string;
  verification: { checkedAt: string; advisorySources: string[]; registrySource?: string; candidateAdvisoryStatus: 'no-known' | 'not-verified'; compatibility: 'NOT TESTED' };
  steps: string[];
  validation: string[];
  recommendationSources: string[];
}
export interface RemediationPlanReport extends ReportContext {
  reportType: 'remediation-plan'; title: 'Remediation Plan'; actions: RemediationAction[];
  coverageActions: string[];
  packageRisk?: PackageRiskReport;
}
export interface ReportBundle {
  id: string; scanId: string; generatedAt: string;
  securityFindings: SecurityFindingsReport;
  remediationPlan: RemediationPlanReport;
}
export interface ReportBundleSummary { id: string; scanId: string; generatedAt: string; findings: number; coverage: VulnerabilityReport['status'] }

export interface PackageRiskResult {
  nodeId: string; name: string; version?: string;
  classification: 'SUSPICIOUS' | 'CONFIRMED MALICIOUS' | 'NO SIGNALS' | 'UNKNOWN';
  metadataStatus: 'available' | 'unavailable' | 'skipped';
  source?: string;
  metadata?: { description: string; license: string; repository?: string; homepage?: string; maintainers: string[]; deprecated?: string; lifecycleScripts: Record<string, string> };
  integrity: { lock?: string; registry?: string; shasum?: string; comparison: 'MATCH' | 'MISMATCH' | 'NOT COMPARABLE'; artifactVerification: 'NOT PERFORMED' };
  provenance: { status: 'ADVERTISED' | 'NOT ADVERTISED' | 'UNKNOWN'; url?: string; signatures: { keyid: string; sig: string }[]; verification: 'NOT PERFORMED' };
  signals: { code: string; explanation: string; evidence: string }[];
  maliciousSources: string[];
  reviewSteps: string[];
}
export interface PackageRiskReport {
  checkedAt: string;
  coverage: { total: number; metadataChecked: number; unavailable: number; skipped: number };
  results: PackageRiskResult[];
  limitations: string[];
  sources: string[];
}

export interface ScanComparison {
  id: string; generatedAt: string;
  before: { scanId: string; createdAt: string; source: string; inventorySha256: string; advisoryCheckedAt: string; inventoryWarnings: string[]; unresolvedDependencies: number };
  after: { scanId: string; createdAt: string; source: string; inventorySha256: string; advisoryCheckedAt: string; inventoryWarnings: string[]; unresolvedDependencies: number };
  counts: Record<'resolved' | 'remaining' | 'newlyIntroduced' | 'unverifiable', number>;
  issues: { packageName: string; ecosystem?: Ecosystem; advisoryId?: string; status: 'resolved' | 'remaining' | 'newlyIntroduced' | 'unverifiable'; before: { nodeId: string; version?: string; installPath: string; project: string; advisoryMatched?: boolean }[]; after: { nodeId: string; version?: string; installPath: string; project: string; advisoryMatched?: boolean }[]; reason: string }[];
  beforeChecks: VulnerabilityReport;
  afterChecks: VulnerabilityReport;
  limitations: string[];
}
