# Solana Account Substitution Security Lab

A focused Solana security lab demonstrating an **account substitution vulnerability** in an Anchor program, its exploitation, and the corresponding secure implementation.

The lab uses Rust, Anchor, and integration tests to demonstrate how an instruction can accidentally allow an unauthorized signer to modify another user's account.

## Overview

The program manages a `Profile` account containing:

- `authority`: the wallet authorized to manage the profile.
- `recovery_wallet`: the designated recovery wallet.
- `status`: profile status information.

The lab implements two versions of the recovery-wallet update instruction.

### 1. Vulnerable implementation

`set_recovery_wallet_vulnerable`

The instruction accepts a profile account and a signer but does not verify that the signer is the authority recorded in that profile.

An attacker can therefore supply:

- The victim's Profile account.
- The attacker's own signing wallet.

The instruction accepts the request and allows the attacker to change the victim's recovery wallet.

### 2. Secure implementation

`set_recovery_wallet_secure`

The secure implementation uses Anchor's `has_one = authority` constraint:

```rust
#[account(mut, has_one = authority)]
pub profile: Account<'info, Profile>,

pub authority: Signer<'info>,
```

This enforces two conditions:

- The supplied account must be a valid `Profile` account.
- The supplied signer must match the authority stored in that profile.

An unauthorized signer cannot modify another user's profile through this instruction.

**Security boundary:** This protects against account substitution by an unauthorized signer. It does not protect against compromise of the legitimate authority's private key.

## Project structure

```text
solana-security-labs-rust/
│
├── Anchor.toml
├── Cargo.toml
├── Cargo.lock
│
├── programs/
│   └── account-substitution-lab/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs
│
├── tests/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       └── account_substitution_attack.rs
│
├── docs/
│   └── account-substitution.md
│
└── diagrams/
    └── account-substitution/
```

## Security tests

The integration test suite demonstrates three scenarios:

| Test | Expected behaviour |
|---|---|
| `account_substitution_attack_works_on_vulnerable_instruction` | Demonstrates successful unauthorized modification |
| `account_substitution_attack_fails_on_secure_instruction` | Confirms the secure instruction rejects the attacker and preserves profile state |
| `successful_secure_instruction` | Confirms the legitimate authority can update the recovery wallet |

The tests verify both transaction outcomes and resulting account state.

## Prerequisites

- Rust and Cargo
- Solana CLI
- Anchor CLI 0.32.1
- A configured Solana wallet at `~/.config/solana/id.json`

## Running the tests

Start a local validator in a separate terminal:

```bash
solana-test-validator
```

Then, from the project root:

```bash
anchor test
```

Anchor handles the local validator lifecycle, program build, deployment, and test execution.

For an already running local validator:

```bash
anchor test --skip-local-validator
```

For faster test execution when the program has not changed and is already deployed to the running validator:

```bash
anchor test --skip-local-validator --skip-build --skip-deploy
```

**Note:** The skip-build and skip-deploy flags are intended only when the deployed program matches the source code being tested.

## Documentation

See [`docs/account-substitution.md`](docs/account-substitution.md) for the detailed vulnerability explanation, attack flow, and secure implementation.

## Purpose

This lab demonstrates practical Solana smart contract security concepts:

- Account validation and ownership.
- Authentication versus authorization.
- Anchor account constraints.
- Signer validation.
- Exploit reproduction and security regression testing.
