import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync, existsSync } from 'fs';
import { AgentPass } from '@agentpass/core';
import { KeyManager } from '@agentpass/crypto';

export function verifyCommand(program: Command) {
  program
    .command('verify')
    .description('Verify an agent credential')
    .requiredOption('--credential <path>', 'Path to credential JSON file')
    .option('--issuer-key <path>', 'Path to issuer public key file')
    .action(async (options) => {
      const spinner = ora('Verifying credential...').start();

      try {
        if (!existsSync(options.credential)) {
          spinner.fail(`Credential file not found: ${options.credential}`);
          process.exit(1);
        }

        const credential = JSON.parse(readFileSync(options.credential, 'utf-8'));

        // Basic structural checks
        const checks: { name: string; passed: boolean; detail: string }[] = [];

        // Check required fields
        checks.push({
          name: 'Structure',
          passed: !!(credential.id && credential.issuer && credential.credentialSubject),
          detail: credential.id || 'missing id',
        });

        // Check expiration
        const now = new Date();
        const expiration = new Date(credential.expirationDate);
        checks.push({
          name: 'Expiration',
          passed: expiration > now,
          detail: credential.expirationDate,
        });

        // Check proof exists
        checks.push({
          name: 'Proof',
          passed: !!credential.proof?.signature,
          detail: credential.proof ? 'present' : 'missing',
        });

        // Check capabilities
        const caps = credential.credentialSubject?.capabilities || [];
        checks.push({
          name: 'Capabilities',
          passed: caps.length > 0,
          detail: `${caps.length} capabilities defined`,
        });

        // Check trust level
        const trustLevel = credential.credentialSubject?.trustLevel;
        checks.push({
          name: 'Trust Level',
          passed: trustLevel >= 1 && trustLevel <= 10,
          detail: `Level ${trustLevel}`,
        });

        // If issuer key provided, verify signature
        if (options.issuerKey && existsSync(options.issuerKey)) {
          spinner.text = 'Verifying cryptographic signature...';
          const keyData = JSON.parse(readFileSync(options.issuerKey, 'utf-8'));
          const keyManager = new KeyManager();

          const publicKeys: any = {};
          if (keyData.pqc) {
            const hybridKey = keyManager.deserializeHybridKeyPair(keyData);
            publicKeys.pqcPublicKey = hybridKey.pqc.publicKey;
            publicKeys.classicalPublicKey = hybridKey.classical.publicKey;
          } else {
            const key = keyManager.deserializeKeyPair(keyData);
            if (key.algorithm.startsWith('ml-')) {
              publicKeys.pqcPublicKey = key.publicKey;
            } else {
              publicKeys.classicalPublicKey = key.publicKey;
            }
          }

          const ap = new AgentPass();
          const result = await ap.verifyCredential(credential, publicKeys);

          checks.push({
            name: 'Signature',
            passed: result.signatureValid,
            detail: result.signatureValid ? 'valid' : result.errors.join(', '),
          });
        }

        // Display results
        const allPassed = checks.every((c) => c.passed);
        if (allPassed) {
          spinner.succeed('Credential verification passed');
        } else {
          spinner.fail('Credential verification failed');
        }

        console.log();
        for (const check of checks) {
          const icon = check.passed ? chalk.green('✓') : chalk.red('✗');
          const detail = chalk.dim(check.detail);
          console.log(`  ${icon} ${check.name}: ${detail}`);
        }

        console.log();
        console.log(
          chalk.dim(`  Agent: ${credential.credentialSubject?.name || 'unknown'}`)
        );
        console.log(chalk.dim(`  DID:   ${credential.credentialSubject?.id || 'unknown'}`));

        if (!allPassed) {
          process.exit(1);
        }
      } catch (error) {
        spinner.fail('Verification failed');
        console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
        process.exit(1);
      }
    });
}
