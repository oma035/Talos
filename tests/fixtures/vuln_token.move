module demo::token {
    use sui::coin::{Self, TreasuryCap};

    public struct TOKEN has drop {}

    public entry fun mint_to(amount: u64, recipient: address, ctx: &mut TxContext) {
        // BUG: no capability required, anyone can call this
        let _ = amount; let _ = recipient; let _ = ctx;
    }

    public entry fun burn_safe(cap: &mut TreasuryCap<TOKEN>, amount: u64) {
        let _ = cap; let _ = amount;
    }
}
