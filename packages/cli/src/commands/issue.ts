import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { AgentPass } from '@agentpass/core';
import { KeyManager } from '@agentpass/crypto';

export function issueCommand(program: Command) {
  program
    .command('issue')
    .description('Issue a verifiable credential for an agent')
    .requiredOption('--issuer <did>', 'Issuer DID')
    .requiredOption('--agent <did>', 'Agent DID (subject)')
    .requiredOption('--name <name>', 'Agent name')
    .option('--description <desc>', 'Agent description')
    .option('--capabilities <caps>', 'Comma-separated capabilities', 'read,write')
    .option('--trust-level <level>', 'Trust level 1-10', '5')
    .option('--valid-days <days>', 'Validity period in days', '365')
    .option('--key <path>', 'Path to issuer secret key', '.agentpass/keys/default.secret.json')
    .option('-o, --output <path>', 'Output path for credential')
    .action(async (options) => {
      const spinner = ora('Issuing verifiable credential...').start();

      try {
        // Load issuer keys
        if (!existsSync(options.key)) {
          spinner.fail(`Key file not found: ${options.key}`);
          process.exit(1);
        }

        const keyData = JSON.parse(readFileSync(options.key, 'utf-8'));
        const keyManager = new KeyManager();
        const keys = keyData.pqc
          ? keyManager.deserializeHybridKeyPair(keyData)
          : keyManager.deserializeKeyPair(keyData);

        const capabilities = options.capabilities.split(',').map((c: string) => c.trim());

        const ap = new AgentPass();
        const credential = await ap.issueCredential(
          {
            issuerDID: options.issuer,
            agentDID: options.agent,
            name: options.name,
            description: options.description,
            capabilities,
            permissions: capabilities.map((cap: string) => ({
              resource: '*',
              actions: [cap] as any[],
            })),
            trustLevel: parseInt(options.trustLevel),
            validForDays: parseInt(options.validDays),
          },
          keys
        );

        // Save credential
        const outputPath =
          options.output ||
          `.agentpass/credentials/${credential.id.split(':').pop()}.credential.json`;
        writeFileSync(outputPath, JSON.stringify(credential, null, 2));

        spinner.succeed('Credential issued');
        console.log();
        console.log(chalk.green('  Credential ID: ') + credential.id);
        console.log(chalk.dim(`  Issuer:        ${options.issuer}`));
        console.log(chalk.dim(`  Agent:         ${options.agent}`));
        console.log(chalk.dim(`  Capabilities:  ${capabilities.join(', ')}`));
        console.log(chalk.dim(`  Trust Level:   ${options.trustLevel}`));
        console.log(chalk.dim(`  Expires:       ${credential.expirationDate}`));
        console.log(chalk.dim(`  File:          ${outputPath}`));
      } catch (error) {
        spinner.fail('Credential issuance failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}
