# Solana Security Labs (Rust)

A collection of reproducible Solana smart contract vulnerabilities and exploit demonstrations.

Each lab contains:
- vulnerable instruction
- secure fix
- Rust exploit tests
- documentation explaining the vulnerability.

## Labs

1. [Account Substitution Attack](https://github.com/LoboVH/solana-security-labs-rust/tree/main/programs/account-substitution-lab)
2. Missing Signer Validation
3. PDA Authority Confusion
4. Unchecked CPI Target

## Running the tests

solana-test-validator
anchor test --skip-local-validator

anchor test --skip-local-validator --skip-build --skip-deploy   (Once build is done and no fresh changes inside program)
