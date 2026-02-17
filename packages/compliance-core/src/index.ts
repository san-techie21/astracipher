/**
 * @agentpass/compliance-core
 *
 * Shared compliance engine that all framework-specific modules extend.
 * Customers select which frameworks they need. Each module:
 *   1. Defines credential schema extensions
 *   2. Provides audit trail formatters
 *   3. Generates compliance reports
 *   4. Alerts on compliance gaps
 */

export { ComplianceEngine } from './engine.js';
export {
  type ComplianceModule,
  type ComplianceField,
  type ComplianceGap,
  type ComplianceReport,
  type ComplianceConfig,
  type FrameworkId,
} from './types.js';
export { BaseComplianceModule } from './base-module.js';
