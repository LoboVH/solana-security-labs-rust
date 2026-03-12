use anchor_lang::prelude::*;

declare_id!("9NZqZZggJ4iYsffucSKRzMwpBNXfcC7yKpnL9CsxFkjy");

#[program]
pub mod account_substitution_lab {

    use super::*;

    pub fn initialize_profile(ctx: Context<InitializeProfile>, status: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.authority = ctx.accounts.authority.key();
        profile.status = status;
        Ok(())
    }


    pub fn set_status_vulnerable(ctx: Context<SetStatusVulnerable>, status: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.status = status;
        Ok(())
    }

    pub fn set_status_secure(ctx: Context<SetStatusSecure>, status: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.status = status; 
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
pub struct SetStatusVulnerable<'info> {
    // Vulnerable because it does not check that the authority is the signer of the transaction
    #[account(mut)]
    pub profile: Account<'info, Profile>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetStatusSecure<'info> {
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
    #[max_len(64)]
    pub status: String,
}