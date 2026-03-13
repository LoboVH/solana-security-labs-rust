use anchor_lang::prelude::*;

declare_id!("BT3jcyCmZ7LEiWFJuLoWEVbrwWpdZHmcxnp3XeVRZj53");

#[program]
pub mod missing_signer_admin_lab {
    use super::*;

    pub fn initialize_config(ctx: Context<InitializeConfig>, fee_recipient: Pubkey) -> Result<()> {
        let protocol_config = &mut ctx.accounts.protocol_config;
        protocol_config.admin = ctx.accounts.admin.key();
        protocol_config.fee_recipient = fee_recipient;
        protocol_config.paused = false;
        Ok(())
    }

    pub fn update_fee_recipient_vulnerable(ctx: Context<UpdateFeeRecipientVulnerable>, new_fee_recipient: Pubkey) -> Result<()> {
        let protocol_config = &mut ctx.accounts.protocol_config;

        protocol_config.fee_recipient = new_fee_recipient;
        Ok(())
    }

    pub fn update_fee_recipient_secure(
        ctx: Context<UpdateFeeRecipientSecure>,
        new_fee_recipient: Pubkey,
    ) -> Result<()> {
        let protocol_config = &mut ctx.accounts.protocol_config;
        protocol_config.fee_recipient = new_fee_recipient;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(init, payer = admin, space = 8 + ProtocolConfig::INIT_SPACE)]
    pub protocol_config: Account<'info, ProtocolConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,

}

#[derive(Accounts)]
pub struct UpdateFeeRecipientVulnerable<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK:
    /// Vulnerable: only key equality is checked, not signature.
    pub admin: UncheckedAccount<'info>,

    #[account(mut, has_one = admin)]
    pub protocol_config: Account<'info, ProtocolConfig>,
}

#[derive(Accounts)]
pub struct UpdateFeeRecipientSecure<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub admin: Signer<'info>,

    #[account(mut, has_one = admin)]
    pub protocol_config: Account<'info, ProtocolConfig>,
}

#[account]
#[derive(InitSpace)]
pub struct ProtocolConfig {
    pub admin: Pubkey,
    pub fee_recipient: Pubkey,
    pub paused: bool,
}

#[error_code]
pub enum AdminError {
    #[msg("Provided admin does not match config.admin")]
    InvalidAdmin,
}
