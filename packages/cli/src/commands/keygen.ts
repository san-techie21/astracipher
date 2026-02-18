import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { AgentPassCrypto, KeyManager } from '@agentpass/crypto';

/**
 * HIGH-6 FIX: Secret keys are now encrypted at rest using AES-256-GCM
 * with a passphrase-derived key (scrypt).
 *
 * File format for encrypted keys:
 * {
 *   encrypted: true,
 *   algorithm: "aes-256-gcm",
 *   kdf: "scrypt",
 *   salt: "<hex>",       // 32 bytes
 *   iv: "<hex>",         // 16 bytes
 *   tag: "<hex>",        // 16 bytes (GCM auth tag)
 *   ciphertext: "<hex>", // encrypted JSON
 *   keyId: "<id>"        // unencrypted for identification
 * }
 */

const ENCRYPTION_ALGO = 'aes-256-gcm';
const SCRYPT_N = 2 ** 15; // scrypt cost parameter
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32; // 256-bit key

function encryptSecretKey(
  data: Record<string, unknown>,
  passphrase: string
): Record<string, unknown> {
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const key = scryptSync(passphrase, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });

  const cipher = createCipheriv(ENCRYPTION_ALGO, key, iv);
  const plaintext = JSON.stringify(data);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    encrypted: true,
    algorithm: ENCRYPTION_ALGO,
    kdf: 'scrypt',
    kdfParams: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: encrypted.toString('hex'),
    keyId: (data as any).keyId || (data as any).pqc?.keyId || 'unknown',
  };
}

export function keygenCommand(program: Command) {
  program
    .command('keygen')
    .description('Generate cryptographic key pairs for agent identity')
    .option('-m, --mode <mode>', 'Crypto mode: hybrid, pqc-only, classical-only', 'hybrid')
    .option('-o, --output <path>', 'Output directory', '.agentpass/keys')
    .option('--name <name>', 'Key name identifier', 'default')
    .option('--passphrase <passphrase>', 'Passphrase to encrypt secret key (or set AGENTPASS_PASSPHRASE env var)')
    .option('--no-encrypt', 'Save secret key as plaintext (NOT recommended)')
    .action(async (options) => {
      // LOW-2 FIX: Validate CLI inputs before processing
      const validModes = ['hybrid', 'pqc-only', 'classical-only'];
      if (!validModes.includes(options.mode)) {
        console.error(chalk.red(`Invalid mode: "${options.mode}". Must be one of: ${validModes.join(', ')}`));
        process.exit(1);
      }

      const nameRegex = /^[a-zA-Z0-9_\-.]{1,64}$/;
      if (!nameRegex.test(options.name)) {
        console.error(chalk.red('Invalid key name. Use 1-64 chars: alphanumeric, hyphens, underscores, or dots.'));
        process.exit(1);
      }

      if (options.output && options.output.includes('..')) {
        console.error(chalk.red('Invalid output path: must not contain ".." traversal'));
        process.exit(1);
      }

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

        // Ensure output directory exists
        if (!existsSync(options.output)) {
          mkdirSync(options.output, { recursive: true });
        }

        // Save public key
        const pubPath = `${options.output}/${options.name}.pub.json`;
        writeFileSync(pubPath, JSON.stringify(publicKeyData, null, 2));

        // Save secret key — encrypted by default
        const secPath = `${options.output}/${options.name}.secret.json`;
        const passphrase = options.passphrase || process.env.AGENTPASS_PASSPHRASE;

        if (options.encrypt !== false && passphrase) {
          // HIGH-6 FIX: Encrypt secret key at rest
          spinner.text = 'Encrypting secret key...';
          const encryptedData = encryptSecretKey(secretKeyData, passphrase);
          writeFileSync(secPath, JSON.stringify(encryptedData, null, 2));

          // Set restrictive file permissions (owner read/write only)
          try {
            chmodSync(secPath, 0o600);
          } catch {
            // chmodSync may fail on Windows — that's okay, we still encrypted
          }

          spinner.succeed('Key pair generated (secret key encrypted)');
          console.log();
          console.log(chalk.green('  Public key:  ') + pubPath);
          console.log(chalk.red('  Secret key:  ') + secPath + chalk.dim(' (AES-256-GCM encrypted)'));
        } else if (options.encrypt === false) {
          // User explicitly requested no encryption
          writeFileSync(secPath, JSON.stringify(secretKeyData, null, 2));
          try {
            chmodSync(secPath, 0o600);
          } catch {
            // Windows may not support chmod
          }

          spinner.succeed('Key pair generated');
          console.log();
          console.log(chalk.green('  Public key:  ') + pubPath);
          console.log(chalk.red('  Secret key:  ') + secPath + chalk.dim(' (PLAINTEXT — consider encrypting!)'));
          console.log(chalk.yellow('  ⚠ Secret key is NOT encrypted. Use --passphrase for production.'));
        } else {
          // No passphrase provided — save plaintext but warn loudly
          writeFileSync(secPath, JSON.stringify(secretKeyData, null, 2));
          try {
            chmodSync(secPath, 0o600);
          } catch {
            // Windows
          }

          spinner.succeed('Key pair generated');
          console.log();
          console.log(chalk.green('  Public key:  ') + pubPath);
          console.log(chalk.red('  Secret key:  ') + secPath);
          console.log(chalk.yellow('  ⚠ Secret key is NOT encrypted!'));
          console.log(chalk.yellow('    Use --passphrase <pass> or set AGENTPASS_PASSPHRASE to encrypt.'));
        }

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
