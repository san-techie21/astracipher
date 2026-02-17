/**
 * Compliance framework type definitions
 */

export type FrameworkId =
  // India
  | 'dpdp'
  | 'sebi-cscrf'
  | 'rbi'
  // EU
  | 'eu-ai-act'
  | 'gdpr'
  | 'uk-ai'
  // US
  | 'hipaa'
  | 'soc2'
  | 'nist-rmf'
  // Global Standards
  | 'iso-42001'
  // Asia-Pacific
  | 'sg-ai'
  | 'jp-ai'
  | 'kr-ai'
  // Americas (future)
  | 'ca-aida'
  | 'br-ai'
  | 'mx-ai';

export interface ComplianceField {
  /** Field key (e.g., 'consentReference') */
  key: string;
  /** Human-readable label */
  label: string;
  /** Data type */
  type: 'string' | 'boolean' | 'number' | 'date' | 'enum' | 'array';
  /** Whether the field is required for compliance */
  required: boolean;
  /** Description of what the field is for */
  description: string;
  /** Allowed values for enum type */
  enumValues?: string[];
  /** Default value */
  defaultValue?: unknown;
}

export interface ComplianceGap {
  /** Framework this gap belongs to */
  framework: FrameworkId;
  /** The missing or invalid field */
  field: string;
  /** Severity of the gap */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** What needs to be done */
  remediation: string;
  /** Regulatory deadline if any */
  deadline?: string;
}

export interface ComplianceReport {
  /** Framework this report is for */
  framework: FrameworkId;
  /** Report title */
  title: string;
  /** Organization DID */
  organizationDID: string;
  /** Reporting period */
  period: { from: string; to: string };
  /** Overall compliance score (0-100) */
  score: number;
  /** Sections of the report */
  sections: ComplianceReportSection[];
  /** Gaps found */
  gaps: ComplianceGap[];
  /** Generated at */
  generatedAt: string;
  /** Report format version */
  formatVersion: string;
}

export interface ComplianceReportSection {
  title: string;
  content: string;
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
  evidence: string[];
}

export interface ComplianceConfig {
  /** Organization DID */
  organizationDID: string;
  /** Active frameworks */
  frameworks: FrameworkId[];
  /** Reporting period */
  reportingPeriod: 'monthly' | 'quarterly' | 'annually';
  /** Webhook for gap alerts */
  alertWebhook?: string;
  /** Server URL for audit trail queries */
  serverUrl?: string;
}

/**
 * Interface that all compliance modules must implement
 */
export interface ComplianceModule {
  /** Framework identifier */
  id: FrameworkId;
  /** Human-readable name */
  name: string;
  /** Version of the module */
  version: string;
  /** Required credential fields for this framework */
  getRequiredFields(): ComplianceField[];
  /** Validate compliance data against framework requirements */
  validateCompliance(data: Record<string, unknown>): ComplianceGap[];
  /** Generate a compliance report */
  generateReport(
    organizationDID: string,
    period: { from: string; to: string },
    auditData: any[]
  ): Promise<ComplianceReport>;
  /** Build compliance payload for credential issuance */
  buildPayload(data: Record<string, unknown>): Record<string, unknown>;
}
