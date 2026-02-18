import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join, resolve } from 'path';

interface ScanIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
}

interface ScanResult {
  target: string;
  issues: ScanIssue[];
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
        const results = await performScan(resolve(options.target));
        spinner.stop();

        if (options.format === 'json') {
          console.log(JSON.stringify(results, null, 2));
          return;
        }

        console.log(chalk.bold.cyan('\n═══ AstraCipher Security Scan ═══\n'));
        console.log(chalk.dim(`  Target: ${resolve(options.target)}`));
        console.log();

        const totalIssues = results.reduce((sum, r) => sum + r.issues.length, 0);
        const criticals = results.reduce((sum, r) => sum + r.issues.filter((i) => i.severity === 'critical').length, 0);
        const highs = results.reduce((sum, r) => sum + r.issues.filter((i) => i.severity === 'high').length, 0);

        if (totalIssues === 0) {
          console.log(chalk.green('  ✓ No issues found — your setup looks secure!'));
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
              const icon = issue.severity === 'critical' ? chalk.red('✗') : issue.severity === 'high' ? chalk.yellow('!') : chalk.dim('•');
              const severity = issue.severity === 'critical' ? chalk.red(`[${issue.severity}]`) : issue.severity === 'high' ? chalk.yellow(`[${issue.severity}]`) : chalk.dim(`[${issue.severity}]`);
              console.log(`    ${icon} ${severity} ${issue.title}`);
              console.log(chalk.dim(`      ${issue.description}`));
            }
            console.log();
          }
        }

        console.log(chalk.dim('  Scan complete. Fix critical issues and add AstraCipher identity.'));
        console.log(chalk.dim('  Learn more: https://astracipher.com/docs/security-scan'));
        console.log();

        if (criticals > 0) process.exit(2);
        else if (highs > 0) process.exit(1);
      } catch (error) {
        spinner.fail('Scan failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}

async function performScan(target: string): Promise<ScanResult[]> {
  const results: ScanResult[] = [];

  // 1. Check for .astracipher/ directory (AstraCipher initialization)
  results.push(checkAstraCipherInit(target));

  // 2. Check MCP server configurations
  results.push(checkMCPConfig(target));

  // 3. Check credential files
  results.push(checkCredentials(target));

  // 4. Check key security
  results.push(checkKeySecurity(target));

  // 5. Check environment for secrets
  results.push(checkEnvironment(target));

  return results;
}

function checkAstraCipherInit(target: string): ScanResult {
  const issues: ScanIssue[] = [];
  const apDir = join(target, '.astracipher');

  if (!existsSync(apDir)) {
    issues.push({
      severity: 'high',
      title: 'No AstraCipher identity configured',
      description: 'No .astracipher/ directory found. Run "astracipher init" to set up identity.',
    });
    return { target: 'Agent Identity', issues };
  }

  // Check config exists
  const configPath = join(apDir, 'config.json');
  if (!existsSync(configPath)) {
    issues.push({
      severity: 'high',
      title: 'Missing AstraCipher configuration',
      description: '.astracipher/ directory exists but config.json is missing.',
    });
  } else {
    try {
      const config = JSON.parse(readFileSync(configPath, 'utf-8'));
      if (config.network === 'mainnet' && !config.serverUrl) {
        issues.push({
          severity: 'medium',
          title: 'Mainnet without verification server',
          description: 'Running on mainnet without a verification server URL configured.',
        });
      }
    } catch {
      issues.push({
        severity: 'medium',
        title: 'Invalid config.json',
        description: '.astracipher/config.json is not valid JSON.',
      });
    }
  }

  // Check for keys
  const keysDir = join(apDir, 'keys');
  if (!existsSync(keysDir)) {
    issues.push({
      severity: 'high',
      title: 'No cryptographic keys generated',
      description: 'No keys/ directory found. Run "astracipher keygen --algo hybrid" to generate keys.',
    });
  }

  // Check for .gitignore protecting keys
  const gitignore = join(apDir, '.gitignore');
  if (existsSync(keysDir) && !existsSync(gitignore)) {
    issues.push({
      severity: 'critical',
      title: 'Key files may be committed to git',
      description: 'No .gitignore in .astracipher/ — private keys could be exposed in version control.',
    });
  }

  if (issues.length === 0) {
    return { target: 'Agent Identity', issues: [] };
  }

  return { target: 'Agent Identity', issues };
}

function checkMCPConfig(target: string): ScanResult {
  const issues: ScanIssue[] = [];

  // Look for MCP config files in common locations
  const mcpConfigLocations = [
    join(target, 'mcp.json'),
    join(target, '.mcp.json'),
    join(target, 'claude_desktop_config.json'),
    join(target, '.claude', 'settings.json'),
  ];

  let foundMcpConfig = false;

  for (const configPath of mcpConfigLocations) {
    if (!existsSync(configPath)) continue;
    foundMcpConfig = true;

    try {
      const config = JSON.parse(readFileSync(configPath, 'utf-8'));
      const servers = config.mcpServers || {};

      for (const [name, serverConfig] of Object.entries(servers)) {
        const sc = serverConfig as any;

        // Check if AstraCipher MCP server is configured
        const isAstraCipherMcp = sc.command?.includes('astracipher') || sc.args?.some?.((a: string) => a.includes('astracipher'));

        if (!isAstraCipherMcp) {
          // Check for exposed tools without auth
          if (!sc.env?.ASTRACIPHER_KEY && !sc.env?.API_KEY) {
            issues.push({
              severity: 'high',
              title: `MCP server "${name}" has no auth credentials`,
              description: `Server "${name}" does not have ASTRACIPHER_KEY or API_KEY in environment. Tools are exposed without agent authentication.`,
            });
          }
        }
      }

      if (Object.keys(servers).length > 0) {
        const hasAstraCipher = Object.values(servers).some((s: any) =>
          s.command?.includes('astracipher') || s.args?.some?.((a: string) => a.includes('astracipher'))
        );
        if (!hasAstraCipher) {
          issues.push({
            severity: 'medium',
            title: 'No AstraCipher MCP server configured',
            description: `Found ${Object.keys(servers).length} MCP server(s) but none include @astracipher/mcp-server for identity verification.`,
          });
        }
      }
    } catch {
      issues.push({
        severity: 'low',
        title: `Invalid MCP config at ${configPath}`,
        description: 'Could not parse MCP configuration file.',
      });
    }
  }

  if (!foundMcpConfig) {
    // Not an error — may not be using MCP
    return { target: 'MCP Configuration', issues: [] };
  }

  return { target: 'MCP Configuration', issues };
}

function checkCredentials(target: string): ScanResult {
  const issues: ScanIssue[] = [];
  const credsDir = join(target, '.astracipher', 'credentials');

  if (!existsSync(credsDir)) {
    return { target: 'Credential Management', issues: [] };
  }

  try {
    const files = readdirSync(credsDir).filter((f) => f.endsWith('.json'));

    for (const file of files) {
      try {
        const cred = JSON.parse(readFileSync(join(credsDir, file), 'utf-8'));

        // Check expiration
        if (cred.expirationDate) {
          const expDate = new Date(cred.expirationDate);
          const now = new Date();
          const daysLeft = (expDate.getTime() - now.getTime()) / 86400000;

          if (daysLeft < 0) {
            issues.push({
              severity: 'high',
              title: `Expired credential: ${file}`,
              description: `Credential expired on ${cred.expirationDate}. Remove or reissue it.`,
            });
          } else if (daysLeft < 30) {
            issues.push({
              severity: 'medium',
              title: `Credential expiring soon: ${file}`,
              description: `Credential expires in ${Math.floor(daysLeft)} days (${cred.expirationDate}).`,
            });
          } else if (daysLeft > 730) {
            issues.push({
              severity: 'low',
              title: `Long-lived credential: ${file}`,
              description: `Credential valid for ${Math.floor(daysLeft)} days. Consider shorter validity periods.`,
            });
          }
        }

        // Check proof
        if (!cred.proof || !cred.proof.signature) {
          issues.push({
            severity: 'high',
            title: `Unsigned credential: ${file}`,
            description: 'Credential has no cryptographic proof. It cannot be verified.',
          });
        }
      } catch {
        issues.push({
          severity: 'low',
          title: `Malformed credential: ${file}`,
          description: 'Could not parse credential JSON.',
        });
      }
    }
  } catch {
    // Can't read directory
  }

  return { target: 'Credential Management', issues };
}

function checkKeySecurity(target: string): ScanResult {
  const issues: ScanIssue[] = [];
  const keysDir = join(target, '.astracipher', 'keys');

  if (!existsSync(keysDir)) {
    return { target: 'Key Security', issues: [] };
  }

  try {
    const files = readdirSync(keysDir);
    const secretKeys = files.filter((f) => f.includes('secret') || f.includes('private'));

    // Check if secret keys have overly permissive permissions (Unix only)
    for (const secretFile of secretKeys) {
      const fullPath = join(keysDir, secretFile);
      try {
        const stats = statSync(fullPath);
        const mode = (stats.mode & 0o777).toString(8);
        // On Unix, check if group/other can read
        if (parseInt(mode) > 600) {
          issues.push({
            severity: 'high',
            title: `Overly permissive key file: ${secretFile}`,
            description: `Key file has permissions ${mode}. Should be 600 (owner read/write only).`,
          });
        }
      } catch {
        // Can't stat — likely Windows, skip permission check
      }
    }

    // Check if both PQC and classical keys exist (hybrid mode)
    const hasPqcKey = files.some((f) => f.includes('pqc') || f.includes('ml-dsa'));
    const hasClassicalKey = files.some((f) => f.includes('ecdsa') || f.includes('classical'));
    const hasHybridKey = files.some((f) => f.includes('hybrid'));

    if (!hasHybridKey && !hasPqcKey) {
      issues.push({
        severity: 'medium',
        title: 'No post-quantum keys found',
        description: 'Only classical keys detected. Generate hybrid keys with "astracipher keygen --algo hybrid" for quantum resistance.',
      });
    }
  } catch {
    // Can't read directory
  }

  return { target: 'Key Security', issues };
}

function checkEnvironment(target: string): ScanResult {
  const issues: ScanIssue[] = [];

  // Check .env files for exposed secrets
  const envFiles = ['.env', '.env.local', '.env.production'];

  for (const envFile of envFiles) {
    const envPath = join(target, envFile);
    if (!existsSync(envPath)) continue;

    try {
      const content = readFileSync(envPath, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;

        const [key] = trimmed.split('=');
        const upperKey = key.toUpperCase().trim();

        // Check for hardcoded secrets
        if (
          (upperKey.includes('SECRET') || upperKey.includes('PRIVATE_KEY') || upperKey.includes('PASSWORD')) &&
          !trimmed.includes('your-') && !trimmed.includes('changeme') && !trimmed.includes('example')
        ) {
          issues.push({
            severity: 'high',
            title: `Potential secret in ${envFile}: ${key.trim()}`,
            description: `Environment variable "${key.trim()}" appears to contain a secret. Ensure .env files are in .gitignore.`,
          });
        }
      }

      // Check if .env is in .gitignore
      const gitignorePath = join(target, '.gitignore');
      if (existsSync(gitignorePath)) {
        const gitignore = readFileSync(gitignorePath, 'utf-8');
        if (!gitignore.includes('.env')) {
          issues.push({
            severity: 'critical',
            title: `.env files not in .gitignore`,
            description: 'Environment files containing secrets may be committed to version control.',
          });
        }
      }
    } catch {
      // Can't read file
    }
  }

  return { target: 'Environment Security', issues };
}
