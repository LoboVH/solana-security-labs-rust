# Solana Security Lab: [Missing Signer Admin Attack](https://github.com/LoboVH/solana-security-labs-rust/tree/main/programs/missing-signer-admin-lab)
This lab demonstrates a missing signer validation vulnerability in Solana programs where privileged admin actions fail to verify that the admin actually signed the transaction.

Without proper signer enforcement, an attacker can impersonate the admin account in instruction inputs and perform privileged state changes.

This vulnerability class has appeared in multiple real-world Solana audits.

## Vulnerability Type

### Missing Signer Validation

When a program relies on an account key (e.g. admin) for authorization but does not require the account to be a signer, any attacker can pass the admin public key in the instruction.

Because public keys are public information, this allows unauthorized access to privileged instructions.

## Real World Relevance

This vulnerability class has appeared in multiple real-world Solana audits.

## Vulnerable Code

```
    #[derive(Accounts)]
    pub struct UpdateFeeRecipientVulnerable<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        /// CHECK: not enforced as signer
        pub admin: UncheckedAccount<'info>,

        #[account(mut, has_one = admin)]
        pub protocol_config: Account<'info, ProtocolConfig>,
    }
 ```

 The program verifies:

 ```
    protocol_config.admin == admin.key()
  ```

However:

admin is not required to sign the transaction

Any attacker can provide the admin public key

This allows admin impersonation.

## Attack steps:

 1. Protocol initialized with a legitimate admin
 2. Attacker calls vulnerable instruction
 3. Attacker supplies the admin public key
 4. Transaction succeeds
 5. Protocol state is modified

 ## Proof of Exploit

 ```
    pub struct UpdateFeeRecipientVulnerable<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK:
    /// Vulnerable: only key equality is checked, not signature.
    pub admin: UncheckedAccount<'info>,

    #[account(mut, has_one = admin)]
    pub protocol_config: Account<'info, ProtocolConfig>,
    }
 ```


The [Rust integration test](https://github.com/LoboVH/solana-security-labs-rust/blob/main/tests/src/missing_signer_admin.rs) demonstrates that an attacker can successfully call the vulnerable instruction posing as an admin.

```
    assert_eq!(after_attack.fee_recipient, attacker.pubkey());
    assert_eq!(after_attack.admin, real_admin.pubkey());
    assert!(!after_attack.paused);
```

after attack, attacker succesfully managed to update fee recipient to their address.

 ## Secure Version

Marking admin account as `Signer` ensures that admin must sign this instruction, otherwise it fails at instruction signing step.

```
    pub struct UpdateFeeRecipientSecure<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub admin: Signer<'info>, // Secure Signer enforced

    #[account(mut, has_one = admin)]
    pub protocol_config: Account<'info, ProtocolConfig>,
    }
 ```

 Attacker fails at layer-1 instruction signing step.

 ## Security Lesson

Solana programs must enforce both identity and signature checks for privileged actions.

## To run this LAB:

Run the local validator first,
```
    solana-test-validator

 ```
then in another tab:
```

    anchor test --skip-local-validator
```
