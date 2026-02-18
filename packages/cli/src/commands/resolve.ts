import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { AgentPass } from '@agentpass/core';
import { readFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';

export function resolveCommand(program: Command) {
  program
    .command('resolve')
    .description('Resolve a DID from the AgentPass registry')
    .requiredOption('--did <did>', 'DID to resolve (e.g. did:agentpass:testnet:abc123)')
    .option('--server <url>', 'Registry server URL')
    .option('--format <format>', 'Output format: pretty, json', 'pretty')
    .option('--verify', 'Verify the DID document signature', false)
    .action(async (options) => {
      const spinner = ora(`Resolving ${options.did}...`).start();

      try {
        // Determine registry URL (CLI flag > config > env > default)
        let registryUrl = options.server || process.env.AGENTPASS_REGISTRY_URL;

        if (!registryUrl) {
          // Try to read from local config
          const configPath = join(resolve('.'), '.agentpass', 'config.json');
          if (existsSync(configPath)) {
            try {
              const config = JSON.parse(readFileSync(configPath, 'utf-8'));
              registryUrl = config.serverUrl || config.registryUrl;
            } catch {
              // ignore parse errors
            }
          }
        }

        if (!registryUrl) {
          registryUrl = 'http://localhost:3456';
        }

        const ap = new AgentPass({ registryUrl });
        const didDocument = await ap.resolveAgent(options.did);

        spinner.stop();

        if (!didDocument) {
          console.log(chalk.red(`\n  ✗ DID not found: ${options.did}`));
          console.log(chalk.dim(`    Registry: ${registryUrl}`));
          console.log(chalk.dim('    The DID may not be registered or the registry may be offline.\n'));
          process.exit(1);
        }

        if (options.format === 'json') {
          console.log(JSON.stringify(didDocument, null, 2));
          return;
        }

        // Pretty print
        console.log(chalk.bold.cyan('\n═══ DID Resolution ═══\n'));
        console.log(chalk.green('  DID:          ') + didDocument.id);
        console.log(chalk.dim('  Controller:   ') + (Array.isArray(didDocument.controller) ? didDocument.controller.join(', ') : didDocument.controller));
        console.log(chalk.dim('  Created:      ') + didDocument.created);
        console.log(chalk.dim('  Updated:      ') + didDocument.updated);
        console.log(chalk.dim('  Deactivated:  ') + (didDocument.deactivated ? chalk.red('yes') : chalk.green('no')));
        console.log(chalk.dim('  Registry:     ') + registryUrl);

        if (didDocument.verificationMethod?.length) {
          console.log(chalk.bold('\n  Verification Methods:'));
          for (const vm of didDocument.verificationMethod) {
            const typeLabel = vm.type === 'ML-DSA-65-2024'
              ? chalk.magenta(vm.type) + chalk.dim(' (post-quantum)')
              : chalk.blue(vm.type) + chalk.dim(' (classical)');
            console.log(`    • ${chalk.dim(vm.id)}`);
            console.log(`      Type: ${typeLabel}`);
          }
        }

        if (didDocument.service?.length) {
          console.log(chalk.bold('\n  Services:'));
          for (const svc of didDocument.service) {
            console.log(chalk.dim(`    • ${svc.type}: ${svc.serviceEndpoint}`));
          }
        }

        // Optionally verify the DID document signature
        if (options.verify) {
          const verifySpinner = ora('  Verifying DID signature...').start();
          try {
            const isValid = await ap.verifyDID(didDocument);
            if (isValid) {
              verifySpinner.succeed(chalk.green('  DID document signature is valid (hybrid PQC + ECDSA)'));
            } else {
              verifySpinner.fail(chalk.red('  DID document signature is INVALID'));
              process.exit(2);
            }
          } catch (err) {
            verifySpinner.fail(chalk.red(`  Signature verification error: ${(err as Error).message}`));
          }
        } else {
          console.log(chalk.dim(`\n  Proof: ${didDocument.proof ? 'present (use --verify to check)' : 'none'}`));
        }

        console.log();
      } catch (error) {
        spinner.fail('Resolution failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}
