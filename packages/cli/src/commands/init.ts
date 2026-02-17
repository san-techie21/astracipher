import { Command } from 'commander';
import chalk from 'chalk';
import { writeFileSync, mkdirSync, existsSync } from 'fs';

export function initCommand(program: Command) {
  program
    .command('init')
    .description('Initialize AgentPass in the current project')
    .option('-n, --network <network>', 'Network: mainnet, testnet, local', 'testnet')
    .option('--force', 'Overwrite existing configuration')
    .action(async (options) => {
      const configDir = '.agentpass';
      const configFile = `${configDir}/config.json`;

      if (existsSync(configDir) && !options.force) {
        console.log(
          chalk.yellow('AgentPass already initialized. Use --force to reinitialize.')
        );
        return;
      }

      mkdirSync(configDir, { recursive: true });
      mkdirSync(`${configDir}/keys`, { recursive: true });
      mkdirSync(`${configDir}/credentials`, { recursive: true });

      const config = {
        version: '0.1.0',
        network: options.network,
        registryUrl:
          options.network === 'mainnet'
            ? 'https://registry.agentpass.dev'
            : options.network === 'testnet'
              ? 'https://testnet.registry.agentpass.dev'
              : 'http://localhost:3456',
        crypto: {
          mode: 'hybrid',
          signatureAlgorithm: 'ml-dsa-65',
          classicalSignatureAlgorithm: 'ecdsa-p256',
          kemAlgorithm: 'ml-kem-768',
        },
        createdAt: new Date().toISOString(),
      };

      writeFileSync(configFile, JSON.stringify(config, null, 2));

      // Create .gitignore for keys
      writeFileSync(
        `${configDir}/.gitignore`,
        'keys/\n*.secret.json\n'
      );

      console.log(chalk.green('✓ AgentPass initialized'));
      console.log(chalk.dim(`  Network: ${options.network}`));
      console.log(chalk.dim(`  Config:  ${configFile}`));
      console.log(chalk.dim(`  Keys:    ${configDir}/keys/`));
      console.log();
      console.log('Next steps:');
      console.log(chalk.cyan('  agentpass keygen     ') + '  Generate identity keys');
      console.log(chalk.cyan('  agentpass create     ') + '  Create an agent DID');
      console.log(chalk.cyan('  agentpass issue      ') + '  Issue a credential');
    });
}
