#!/usr/bin/env node

/**
 * AstraCipher CLI
 *
 * Commands:
 *   init      - Initialize AstraCipher in a project
 *   keygen    - Generate cryptographic key pairs
 *   create    - Create a new agent DID
 *   issue     - Issue a credential for an agent
 *   verify    - Verify an agent's credential
 *   revoke    - Revoke a credential
 *   inspect   - Inspect a DID document or credential
 *   resolve   - Resolve a DID from the registry
 *   scan      - Scan MCP servers for security issues
 *   export    - Export credentials/DIDs to file
 */

import { Command } from 'commander';
import { initCommand } from './commands/init.js';
import { keygenCommand } from './commands/keygen.js';
import { createCommand } from './commands/create.js';
import { issueCommand } from './commands/issue.js';
import { verifyCommand } from './commands/verify.js';
import { inspectCommand } from './commands/inspect.js';
import { scanCommand } from './commands/scan.js';
import { resolveCommand } from './commands/resolve.js';

const program = new Command();

program
  .name('astracipher')
  .description(
    'Open-source identity & trust protocol for AI agents.\n' +
      'The SSL certificates of the agent economy.'
  )
  .version('0.1.0');

// Register commands
initCommand(program);
keygenCommand(program);
createCommand(program);
issueCommand(program);
verifyCommand(program);
inspectCommand(program);
scanCommand(program);
resolveCommand(program);

program.parse();
