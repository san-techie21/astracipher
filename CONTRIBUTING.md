# Contributing to AstraCipher

Thank you for your interest in contributing to AstraCipher! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributor License Agreement (CLA)

Before we can accept your contribution, you must sign our Contributor License Agreement. This ensures that the project can continue to be distributed under its current license terms.

When you submit your first pull request, a CLA bot will guide you through the process.

## How to Contribute

### Reporting Bugs

1. **Search existing issues** first to avoid duplicates
2. Use the **Bug Report** issue template
3. Include:
   - Steps to reproduce
   - Expected vs actual behavior
   - Node.js version and OS
   - Relevant error messages or logs

### Suggesting Features

1. Use the **Feature Request** issue template
2. Describe the use case and why it matters
3. If possible, reference relevant standards (W3C DID, VC, FIPS, WIMSE)

### Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Make your changes** — follow existing code style
5. **Run tests:**
   ```bash
   npm run build
   npm run test
   node e2e-test.mjs
   ```
6. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add support for X"
   ```
7. **Push** and open a PR against `main`

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Adding or updating tests
- `refactor:` — Code refactoring (no feature change)
- `chore:` — Maintenance tasks

### Code Style

- TypeScript strict mode
- ESM modules (`import`/`export`)
- No `any` types unless absolutely necessary
- All public APIs must have JSDoc comments
- Cryptographic code must reference the relevant NIST FIPS standard

## Development Setup

```bash
# Clone the repo
git clone https://github.com/AstraFintechLabs/astracipher.git
cd astracipher

# Install dependencies
npm install

# Build all packages
npx turbo run build

# Run E2E tests
node e2e-test.mjs

# Work on a specific package
cd packages/core
npm run dev
```

## Project Structure

```
packages/
├── core/            # DID, Credentials, Trust Chains
├── crypto/          # Post-quantum + classical cryptography
├── cli/             # Command-line interface
├── compliance-core/ # Compliance framework plugin interface
└── sdk-python/      # Python SDK
integrations/
├── mcp-server/      # Model Context Protocol server
└── a2a-adapter/     # Google A2A protocol adapter
site/                # Project website (astracipher.com)
```

## License

By contributing, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE), which converts to Apache License 2.0 on February 18, 2030.

## Questions?

- Open a [Discussion](https://github.com/AstraFintechLabs/astracipher/discussions)
- Email: [contributors@astracipher.com](mailto:contributors@astracipher.com)
