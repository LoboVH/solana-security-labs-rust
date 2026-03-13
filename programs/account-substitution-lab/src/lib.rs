use anchor_lang::prelude::*;

declare_id!("HDi2L6zCnfqzH1PqNY1qEXBY61eQk2A3TJrrBFjtydii");

#[program]
pub mod account_substitution_lab {

    use super::*;

    pub fn initialize_profile(ctx: Context<InitializeProfile>, recovery_wallet: Pubkey, status: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.authority = ctx.accounts.authority.key();
        profile.recovery_wallet = recovery_wallet;
        profile.status = status;
        Ok(())
    }


    pub fn set_recovery_wallet_vulnerable(ctx: Context<SetRecoveryWalletVulnerable>, new_recovery_wallet: Pubkey) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.recovery_wallet = new_recovery_wallet;
        Ok(())
    }

    pub fn set_recovery_wallet_secure(ctx: Context<SetRecoveryWalletSecure>, new_recovery_wallet: Pubkey) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.recovery_wallet = new_recovery_wallet;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeProfile<'info> {
    #[account(init, payer = authority, space = 8 + Profile::INIT_SPACE)]
    pub profile: Account<'info, Profile>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>
}

#[derive(Accounts)]
pub struct SetRecoveryWalletVulnerable<'info> {
    // Vulnerable because it does not check that the authority is the signer of the transaction
    #[account(mut)]
    pub profile: Account<'info, Profile>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetRecoveryWalletSecure<'info> {
    // Secure because it checks that the authority is the signer of the transaction
    #[account(mut, has_one = authority)]
    pub profile: Account<'info, Profile>,
    #[account(mut)]
    pub authority: Signer<'info>,
}


#[account]
#[derive(InitSpace)]
pub struct Profile {
    pub authority: Pubkey,
    pub recovery_wallet: Pubkey,
    #[max_len(64)]
    pub status: String,
}