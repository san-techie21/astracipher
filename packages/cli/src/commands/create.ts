import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { AstraCipher } from '@astracipher/core';
import { KeyManager } from '@astracipher/crypto';

export function createCommand(program: Command) {
  program
    .command('create')
    .description('Create a new agent DID')
    .requiredOption('--name <name>', 'Agent name')
    .option('--description <desc>', 'Agent description')
    .option('--key <path>', 'Path to secret key file', '.astracipher/keys/default.secret.json')
    .option('--network <network>', 'Network', 'testnet')
    .option('-o, --output <path>', 'Output path for DID document')
    .action(async (options) => {
      // PUB-LOW-6 FIX: Validate CLI inputs
      if (options.name.length > 256) {
        console.error(chalk.red('Invalid name: must be 256 characters or fewer'));
        process.exit(1);
      }
      if (options.description && options.description.length > 1024) {
        console.error(chalk.red('Invalid description: must be 1024 characters or fewer'));
        process.exit(1);
      }
      const validNetworks = ['testnet', 'mainnet'];
      if (!validNetworks.includes(options.network)) {
        console.error(chalk.red(`Invalid network: must be one of: ${validNetworks.join(', ')}`));
        process.exit(1);
      }
      // PUB-LOW-4 FIX: Path traversal check on output
      if (options.output && options.output.includes('..')) {
        console.error(chalk.red('Invalid output path: must not contain ".." traversal'));
        process.exit(1);
      }

      const spinner = ora('Creating agent DID...').start();

      try {
        // Load keys
        if (!existsSync(options.key)) {
          spinner.fail(`Key file not found: ${options.key}`);
          console.log(chalk.dim('Run `astracipher keygen` first to generate keys.'));
          process.exit(1);
        }

        const keyData = JSON.parse(readFileSync(options.key, 'utf-8'));
        const keyManager = new KeyManager();
        const keys = keyData.pqc
          ? keyManager.deserializeHybridKeyPair(keyData)
          : keyManager.deserializeKeyPair(keyData);

        // Create agent
        const ap = new AstraCipher({ network: options.network });
        const { did, didId } = await ap.createAgent({
          name: options.name,
          description: options.description,
        });

        // Save DID document
        const outputPath =
          options.output || `.astracipher/credentials/${didId.replace(/:/g, '_')}.did.json`;
        writeFileSync(outputPath, JSON.stringify(did, null, 2));

        spinner.succeed('Agent DID created');
        console.log();
        console.log(chalk.green('  DID:     ') + didId);
        console.log(chalk.dim(`  Network: ${options.network}`));
        console.log(chalk.dim(`  File:    ${outputPath}`));
        console.log();
        console.log('Next: Issue a credential with:');
        console.log(
          chalk.cyan(`  astracipher issue --issuer ${didId} --agent ${didId} --name "${options.name}"`)
        );
      } catch (error) {
        spinner.fail('DID creation failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}
