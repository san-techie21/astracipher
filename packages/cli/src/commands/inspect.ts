import { Command } from 'commander';
import chalk from 'chalk';
import { readFileSync, existsSync } from 'fs';

export function inspectCommand(program: Command) {
  program
    .command('inspect')
    .description('Inspect a DID document or credential')
    .requiredOption('--file <path>', 'Path to JSON file')
    .option('--format <format>', 'Output format: pretty, json, summary', 'pretty')
    .action(async (options) => {
      if (!existsSync(options.file)) {
        console.error(chalk.red(`File not found: ${options.file}`));
        process.exit(1);
      }

      const data = JSON.parse(readFileSync(options.file, 'utf-8'));

      if (options.format === 'json') {
        console.log(JSON.stringify(data, null, 2));
        return;
      }

      // Detect type
      const isDID = data['@context']?.some((c: string) => c.includes('did'));
      const isCredential = data.type?.includes('VerifiableCredential');

      if (isDID && !isCredential) {
        printDID(data);
      } else if (isCredential) {
        printCredential(data);
      } else {
        console.log(chalk.yellow('Unknown document type'));
        console.log(JSON.stringify(data, null, 2));
      }
    });
}

function printDID(did: any) {
  console.log(chalk.bold.cyan('\n═══ DID Document ═══\n'));
  console.log(chalk.green('  ID:          ') + did.id);
  console.log(chalk.dim('  Controller:  ') + (Array.isArray(did.controller) ? did.controller.join(', ') : did.controller));
  console.log(chalk.dim('  Created:     ') + did.created);
  console.log(chalk.dim('  Updated:     ') + did.updated);
  console.log(chalk.dim('  Deactivated: ') + (did.deactivated ? chalk.red('yes') : chalk.green('no')));

  if (did.verificationMethod?.length) {
    console.log(chalk.bold('\n  Verification Methods:'));
    for (const vm of did.verificationMethod) {
      console.log(chalk.dim(`    • ${vm.id}`));
      console.log(chalk.dim(`      Type: ${vm.type}`));
    }
  }

  if (did.service?.length) {
    console.log(chalk.bold('\n  Services:'));
    for (const svc of did.service) {
      console.log(chalk.dim(`    • ${svc.type}: ${svc.serviceEndpoint}`));
    }
  }

  console.log(chalk.dim(`\n  Proof: ${did.proof ? 'present' : 'none'}`));
  console.log();
}

function printCredential(cred: any) {
  console.log(chalk.bold.cyan('\n═══ Agent Credential ═══\n'));
  console.log(chalk.green('  ID:           ') + cred.id);
  console.log(chalk.dim('  Issuer:       ') + cred.issuer);
  console.log(chalk.dim('  Issued:       ') + cred.issuanceDate);
  console.log(chalk.dim('  Expires:      ') + cred.expirationDate);

  const now = new Date();
  const exp = new Date(cred.expirationDate);
  const daysLeft = Math.floor((exp.getTime() - now.getTime()) / 86400000);
  console.log(
    chalk.dim('  Status:       ') +
      (daysLeft > 0
        ? chalk.green(`valid (${daysLeft} days remaining)`)
        : chalk.red('expired'))
  );

  const subject = cred.credentialSubject;
  if (subject) {
    console.log(chalk.bold('\n  Agent:'));
    console.log(chalk.dim(`    Name:         ${subject.name}`));
    console.log(chalk.dim(`    DID:          ${subject.id}`));
    console.log(chalk.dim(`    Model:        ${subject.model || 'not specified'}`));
    console.log(chalk.dim(`    Trust Level:  ${subject.trustLevel}/10`));
    console.log(chalk.dim(`    Capabilities: ${subject.capabilities?.join(', ')}`));

    if (subject.permissions?.length) {
      console.log(chalk.bold('\n  Permissions:'));
      for (const perm of subject.permissions) {
        console.log(chalk.dim(`    • ${perm.resource}: [${perm.actions.join(', ')}]`));
      }
    }

    if (subject.rateLimits) {
      console.log(chalk.bold('\n  Rate Limits:'));
      if (subject.rateLimits.requestsPerMinute)
        console.log(chalk.dim(`    Per minute: ${subject.rateLimits.requestsPerMinute}`));
      if (subject.rateLimits.requestsPerHour)
        console.log(chalk.dim(`    Per hour:   ${subject.rateLimits.requestsPerHour}`));
    }
  }

  console.log(chalk.dim(`\n  Proof: ${cred.proof ? 'present' : 'none'}`));
  console.log();
}
