use anchor_lang::prelude::*;
#[program]
pub mod t {
    pub fn call(ctx: Context<Call>, data: Vec<u8>) -> Result<()> {
        require_keys_eq!(*ctx.accounts.target.key, TRUSTED_ID);
        let ix = Instruction { program_id: *ctx.accounts.target.key, accounts: vec![], data };
        invoke(&ix, &[ctx.accounts.target.to_account_info()])?;
        Ok(())
    }
}
