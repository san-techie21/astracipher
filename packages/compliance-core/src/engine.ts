/**
 * ComplianceEngine - Orchestrates multiple compliance modules
 *
 * Customers select which frameworks they need.
 * The engine aggregates requirements, validates data, and generates reports.
 */

import type {
  ComplianceConfig,
  ComplianceModule,
  ComplianceField,
  ComplianceGap,
  ComplianceReport,
  FrameworkId,
} from './types.js';

export class ComplianceEngine {
  private config: ComplianceConfig;
  private modules: Map<FrameworkId, ComplianceModule> = new Map();

  constructor(config: ComplianceConfig) {
    this.config = config;
  }

  /**
   * Register a compliance module
   */
  registerModule(module: ComplianceModule): void {
    this.modules.set(module.id, module);
  }

  /**
   * Get all required fields across all active frameworks
   */
  getRequiredFields(): Record<FrameworkId, ComplianceField[]> {
    const result: Record<string, ComplianceField[]> = {};

    for (const frameworkId of this.config.frameworks) {
      const module = this.modules.get(frameworkId);
      if (module) {
        result[frameworkId] = module.getRequiredFields();
      }
    }

    return result as Record<FrameworkId, ComplianceField[]>;
  }

  /**
   * Build compliance payload for credential issuance
   */
  buildCompliancePayload(
    data: Partial<Record<FrameworkId, Record<string, unknown>>>
  ): Record<string, unknown> {
    const payload: Record<string, unknown> = {};

    for (const frameworkId of this.config.frameworks) {
      const module = this.modules.get(frameworkId);
      const frameworkData = data[frameworkId];

      if (module && frameworkData) {
        payload[frameworkId] = module.buildPayload(frameworkData);
      }
    }

    return payload;
  }

  /**
   * Check compliance gaps across all active frameworks
   */
  checkGaps(
    data?: Partial<Record<FrameworkId, Record<string, unknown>>>
  ): ComplianceGap[] {
    const allGaps: ComplianceGap[] = [];

    for (const frameworkId of this.config.frameworks) {
      const module = this.modules.get(frameworkId);
      if (!module) {
        allGaps.push({
          framework: frameworkId,
          field: 'module',
          severity: 'critical',
          remediation: `Compliance module for ${frameworkId} is not installed. Install @agentpass/compliance-${frameworkId}`,
        });
        continue;
      }

      const frameworkData = data?.[frameworkId] || {};
      const gaps = module.validateCompliance(frameworkData);
      allGaps.push(...gaps);
    }

    return allGaps.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  /**
   * Generate compliance reports for all active frameworks
   */
  async generateReports(options: {
    period: { from: string; to: string };
    auditData?: any[];
    format?: 'json' | 'pdf' | 'csv';
  }): Promise<Record<FrameworkId, ComplianceReport>> {
    const reports: Record<string, ComplianceReport> = {};

    for (const frameworkId of this.config.frameworks) {
      const module = this.modules.get(frameworkId);
      if (module) {
        reports[frameworkId] = await module.generateReport(
          this.config.organizationDID,
          options.period,
          options.auditData || []
        );
      }
    }

    return reports as Record<FrameworkId, ComplianceReport>;
  }

  /**
   * Send gap alerts to configured webhook
   */
  async sendAlerts(gaps: ComplianceGap[]): Promise<void> {
    if (!this.config.alertWebhook) return;

    const criticalGaps = gaps.filter(
      (g) => g.severity === 'critical' || g.severity === 'high'
    );

    if (criticalGaps.length === 0) return;

    try {
      await fetch(this.config.alertWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'agentpass:compliance:alert',
          organization: this.config.organizationDID,
          gaps: criticalGaps,
          timestamp: new Date().toISOString(),
        }),
      });
    } catch (error) {
      console.error('Failed to send compliance alert:', error);
    }
  }

  /**
   * Get list of active frameworks
   */
  getActiveFrameworks(): FrameworkId[] {
    return [...this.config.frameworks];
  }

  /**
   * Check if a specific module is registered
   */
  hasModule(frameworkId: FrameworkId): boolean {
    return this.modules.has(frameworkId);
  }
}
