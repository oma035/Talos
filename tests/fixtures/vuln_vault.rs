use anchor_lang::prelude::*;

declare_id!("Vau1t11111111111111111111111111111111111111");

#[program]
pub mod vault {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance += amount;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"vault"])]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
    pub recipient: UncheckedAccount<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
