import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync, existsSync } from 'fs';
import { AgentPassCrypto, KeyManager } from '@agentpass/crypto';

export function keygenCommand(program: Command) {
  program
    .command('keygen')
    .description('Generate cryptographic key pairs for agent identity')
    .option('-m, --mode <mode>', 'Crypto mode: hybrid, pqc-only, classical-only', 'hybrid')
    .option('-o, --output <path>', 'Output directory', '.agentpass/keys')
    .option('--name <name>', 'Key name identifier', 'default')
    .action(async (options) => {
      const spinner = ora('Generating post-quantum key pair...').start();

      try {
        const crypto = new AgentPassCrypto({ mode: options.mode as any });
        const keyManager = crypto.getKeyManager();
        const keys = await crypto.generateIdentityKeys();

        spinner.text = 'Serializing keys...';

        let publicKeyData: any;
        let secretKeyData: any;

        if ('pqc' in keys) {
          // Hybrid key pair
          publicKeyData = keyManager.serializeHybridKeyPair(keys, false);
          secretKeyData = keyManager.serializeHybridKeyPair(keys, true);
        } else {
          publicKeyData = keyManager.serializeKeyPair(keys, false);
          secretKeyData = keyManager.serializeKeyPair(keys, true);
        }

        // Save public key
        const pubPath = `${options.output}/${options.name}.pub.json`;
        writeFileSync(pubPath, JSON.stringify(publicKeyData, null, 2));

        // Save secret key
        const secPath = `${options.output}/${options.name}.secret.json`;
        writeFileSync(secPath, JSON.stringify(secretKeyData, null, 2));

        spinner.succeed('Key pair generated');
        console.log();
        console.log(chalk.green('  Public key:  ') + pubPath);
        console.log(chalk.red('  Secret key:  ') + secPath + chalk.dim(' (keep this safe!)'));
        console.log(chalk.dim(`  Key ID:      ${publicKeyData.keyId || publicKeyData.pqc?.keyId}`));
        console.log(chalk.dim(`  Mode:        ${options.mode}`));
        console.log();
        console.log(
          chalk.yellow('⚠ Never commit secret keys to git. They are .gitignored by default.')
        );
      } catch (error) {
        spinner.fail('Key generation failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}
