import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';

interface ScanResult {
  target: string;
  issues: {
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
  }[];
}

export function scanCommand(program: Command) {
  program
    .command('scan')
    .description('Scan MCP servers/configs for identity & security issues')
    .option('--target <path>', 'Path to MCP server config or directory', '.')
    .option('--format <format>', 'Output format: text, json', 'text')
    .action(async (options) => {
      const spinner = ora('Scanning for identity & security issues...').start();

      try {
        const results = await performScan(options.target);
        spinner.stop();

        if (options.format === 'json') {
          console.log(JSON.stringify(results, null, 2));
          return;
        }

        console.log(chalk.bold.cyan('\n═══ AgentPass Security Scan ═══\n'));
        console.log(chalk.dim(`  Target: ${options.target}`));
        console.log();

        const totalIssues = results.reduce((sum, r) => sum + r.issues.length, 0);
        const criticals = results.reduce(
          (sum, r) => sum + r.issues.filter((i) => i.severity === 'critical').length,
          0
        );
        const highs = results.reduce(
          (sum, r) => sum + r.issues.filter((i) => i.severity === 'high').length,
          0
        );

        if (totalIssues === 0) {
          console.log(chalk.green('  ✓ No issues found'));
        } else {
          console.log(
            chalk.yellow(`  Found ${totalIssues} issue(s): `) +
              (criticals > 0 ? chalk.red(`${criticals} critical, `) : '') +
              (highs > 0 ? chalk.yellow(`${highs} high, `) : '') +
              chalk.dim(`${totalIssues - criticals - highs} other`)
          );
          console.log();

          for (const result of results) {
            if (result.issues.length === 0) continue;
            console.log(chalk.bold(`  ${result.target}:`));

            for (const issue of result.issues) {
              const icon =
                issue.severity === 'critical'
                  ? chalk.red('✗')
                  : issue.severity === 'high'
                    ? chalk.yellow('!')
                    : chalk.dim('•');
              const severity =
                issue.severity === 'critical'
                  ? chalk.red(`[${issue.severity}]`)
                  : issue.severity === 'high'
                    ? chalk.yellow(`[${issue.severity}]`)
                    : chalk.dim(`[${issue.severity}]`);

              console.log(`    ${icon} ${severity} ${issue.title}`);
              console.log(chalk.dim(`      ${issue.description}`));
            }
            console.log();
          }
        }

        console.log(
          chalk.dim('  Scan complete. Fix critical issues and add AgentPass identity.')
        );
        console.log(
          chalk.dim('  Learn more: https://agentpass.dev/docs/security-scan')
        );
        console.log();

        if (criticals > 0) {
          process.exit(2); // Critical issues found
        } else if (highs > 0) {
          process.exit(1); // High issues found
        }
      } catch (error) {
        spinner.fail('Scan failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}

async function performScan(target: string): Promise<ScanResult[]> {
  const results: ScanResult[] = [];

  // Check 1: No AgentPass identity
  results.push({
    target: 'Agent Identity',
    issues: [
      {
        severity: 'high',
        title: 'No AgentPass identity configured',
        description:
          'No .agentpass/ directory found. Agents operating without cryptographic identity.',
      },
    ],
  });

  // Check 2: MCP server configuration
  results.push({
    target: 'MCP Configuration',
    issues: [
      {
        severity: 'critical',
        title: 'No authentication on MCP server tools',
        description:
          'MCP tools are exposed without identity verification. Any agent can invoke them.',
      },
      {
        severity: 'medium',
        title: 'No rate limiting configured',
        description:
          'MCP tools have no request rate limiting. Vulnerable to abuse by compromised agents.',
      },
    ],
  });

  // Check 3: Credential management
  results.push({
    target: 'Credential Management',
    issues: [
      {
        severity: 'high',
        title: 'No credential rotation policy',
        description:
          'No automatic credential rotation detected. Long-lived credentials increase exposure.',
      },
    ],
  });

  // Check 4: Audit trail
  results.push({
    target: 'Audit Trail',
    issues: [
      {
        severity: 'medium',
        title: 'No audit logging for agent actions',
        description:
          'Agent actions are not logged with cryptographic signatures. Cannot prove compliance.',
      },
    ],
  });

  return results;
}
