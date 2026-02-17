import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { AgentPass } from '@agentpass/core';
import { KeyManager } from '@agentpass/crypto';

export function createCommand(program: Command) {
  program
    .command('create')
    .description('Create a new agent DID')
    .requiredOption('--name <name>', 'Agent name')
    .option('--description <desc>', 'Agent description')
    .option('--key <path>', 'Path to secret key file', '.agentpass/keys/default.secret.json')
    .option('--network <network>', 'Network', 'testnet')
    .option('-o, --output <path>', 'Output path for DID document')
    .action(async (options) => {
      const spinner = ora('Creating agent DID...').start();

      try {
        // Load keys
        if (!existsSync(options.key)) {
          spinner.fail(`Key file not found: ${options.key}`);
          console.log(chalk.dim('Run `agentpass keygen` first to generate keys.'));
          process.exit(1);
        }

        const keyData = JSON.parse(readFileSync(options.key, 'utf-8'));
        const keyManager = new KeyManager();
        const keys = keyData.pqc
          ? keyManager.deserializeHybridKeyPair(keyData)
          : keyManager.deserializeKeyPair(keyData);

        // Create agent
        const ap = new AgentPass({ network: options.network });
        const { did, didId } = await ap.createAgent({
          name: options.name,
          description: options.description,
        });

        // Save DID document
        const outputPath =
          options.output || `.agentpass/credentials/${didId.replace(/:/g, '_')}.did.json`;
        writeFileSync(outputPath, JSON.stringify(did, null, 2));

        spinner.succeed('Agent DID created');
        console.log();
        console.log(chalk.green('  DID:     ') + didId);
        console.log(chalk.dim(`  Network: ${options.network}`));
        console.log(chalk.dim(`  File:    ${outputPath}`));
        console.log();
        console.log('Next: Issue a credential with:');
        console.log(
          chalk.cyan(`  agentpass issue --issuer ${didId} --agent ${didId} --name "${options.name}"`)
        );
      } catch (error) {
        spinner.fail('DID creation failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}
