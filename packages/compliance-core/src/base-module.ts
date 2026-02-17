/**
 * Base class for all compliance modules
 */

import type {
  ComplianceModule,
  ComplianceField,
  ComplianceGap,
  ComplianceReport,
  ComplianceReportSection,
  FrameworkId,
} from './types.js';

export abstract class BaseComplianceModule implements ComplianceModule {
  abstract id: FrameworkId;
  abstract name: string;
  abstract version: string;

  abstract getRequiredFields(): ComplianceField[];

  /**
   * Default validation: check all required fields are present
   */
  validateCompliance(data: Record<string, unknown>): ComplianceGap[] {
    const gaps: ComplianceGap[] = [];
    const requiredFields = this.getRequiredFields().filter((f) => f.required);

    for (const field of requiredFields) {
      const value = data[field.key];

      if (value === undefined || value === null || value === '') {
        gaps.push({
          framework: this.id,
          field: field.key,
          severity: 'high',
          remediation: `Provide ${field.label}: ${field.description}`,
        });
      }

      // Type-specific validation
      if (value !== undefined && value !== null) {
        if (field.type === 'boolean' && typeof value !== 'boolean') {
          gaps.push({
            framework: this.id,
            field: field.key,
            severity: 'medium',
            remediation: `${field.label} must be a boolean`,
          });
        }

        if (field.type === 'enum' && field.enumValues && !field.enumValues.includes(value as string)) {
          gaps.push({
            framework: this.id,
            field: field.key,
            severity: 'high',
            remediation: `${field.label} must be one of: ${field.enumValues.join(', ')}`,
          });
        }
      }
    }

    return gaps;
  }

  /**
   * Default report generation structure
   */
  async generateReport(
    organizationDID: string,
    period: { from: string; to: string },
    auditData: any[]
  ): Promise<ComplianceReport> {
    const gaps = this.validateCompliance({});
    const sections = await this.buildReportSections(auditData, period);
    const score = this.calculateComplianceScore(sections, gaps);

    return {
      framework: this.id,
      title: `${this.name} Compliance Report`,
      organizationDID,
      period,
      score,
      sections,
      gaps,
      generatedAt: new Date().toISOString(),
      formatVersion: '1.0',
    };
  }

  /**
   * Override in subclasses for framework-specific sections
   */
  protected async buildReportSections(
    _auditData: any[],
    _period: { from: string; to: string }
  ): Promise<ComplianceReportSection[]> {
    return [
      {
        title: 'Agent Identity Governance',
        content: 'All agents have cryptographic identities issued via AgentPass protocol.',
        status: 'compliant',
        evidence: ['AgentPass DID registry', 'Credential issuance logs'],
      },
      {
        title: 'Audit Trail',
        content: 'All agent actions are logged with cryptographic signatures.',
        status: 'compliant',
        evidence: ['Audit trail API', 'Signed action logs'],
      },
    ];
  }

  /**
   * Calculate compliance score (0-100)
   */
  protected calculateComplianceScore(
    sections: ComplianceReportSection[],
    gaps: ComplianceGap[]
  ): number {
    if (sections.length === 0) return 0;

    const sectionScores = sections.map((s) => {
      switch (s.status) {
        case 'compliant': return 100;
        case 'partial': return 60;
        case 'non-compliant': return 0;
        case 'not-applicable': return 100;
      }
    });

    const avgSectionScore = sectionScores.reduce((a, b) => a + b, 0) / sectionScores.length;

    // Deduct for gaps
    const criticalGaps = gaps.filter((g) => g.severity === 'critical').length;
    const highGaps = gaps.filter((g) => g.severity === 'high').length;
    const deduction = criticalGaps * 15 + highGaps * 8;

    return Math.max(0, Math.round(avgSectionScore - deduction));
  }

  /**
   * Default payload builder - passes through all data
   */
  buildPayload(data: Record<string, unknown>): Record<string, unknown> {
    return { ...data };
  }
}
