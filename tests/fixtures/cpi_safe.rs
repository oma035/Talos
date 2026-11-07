use anchor_lang::prelude::*;
#[program]
pub mod t {
    pub fn pay(ctx: Context<Pay>, amount: u64) -> Result<()> {
        let ix = system_instruction::transfer(&ctx.accounts.from.key(), &ctx.accounts.to.key(), amount);
        invoke(&ix, &[ctx.accounts.from.to_account_info(), ctx.accounts.to.to_account_info()])?;
        Ok(())
    }
}
