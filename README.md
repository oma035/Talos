# Talos 🛡 — smart-contract security guard for Hermes Agent

Hermes can write a Solana (Anchor), Sui (Move) or EVM (Solidity) contract and deploy it in the same session. Talos makes security checks **automatic and unskippable**:

1. **Scan on write.** Every `.rs`, `.move` and `.sol` file Hermes writes is scanned immediately, and the findings are attached to the tool result.
2. **Self-fix.** Open medium+ findings are added to Hermes's context, so it fixes its own bugs before you ask.
3. **Deploy gate.** Before any deploy command runs, Talos rescans the project:
   | Network | Open findings | Result |
   |---|---|---|
   | mainnet / unknown | critical or high | **Blocked** |
   | mainnet / unknown | medium only | **You are asked to approve** (Hermes's own approval prompt, which the model cannot skip) |
   | devnet / testnet / local | any | Allowed, with a warning |
4. **`/talos`** prints an audit report for the current project in any chat (CLI, Telegram, etc.).
5. **`talos_scan` tool** lets Hermes scan any path on demand.

Detected deploys: `anchor deploy|upgrade`, `solana program deploy|upgrade`, `sui client publish|upgrade`, `forge script --broadcast`, `forge create`, `hardhat run|deploy|ignition deploy`, including when hidden inside shell, Python or JS scripts, `package.json` scripts and Makefiles (3 levels deep).

## Install

```bash
hermes plugins install <repo-url>
hermes plugins enable talos      # grant tools.override when asked (see Permissions)
```

Optional analyzers (Talos tells you if one is missing; it never silently skips):
- **EVM:** `pip install slither-analyzer solc-select && solc-select install 0.8.24 && solc-select use 0.8.24`, in the same Python environment as Hermes.
- **Sui:** the `sui` CLI, for `sui move build --lint`.
- **Solana/Anchor:** no install needed (built-in rule pack).

Requires Hermes >= 0.18.1.

## Permissions (disclosure)

- **`tools.override`.** Hermes requires this capability for any plugin whose `pre_tool_call` hook can block or escalate tool calls. Talos **does not replace any built-in tool.** It only inspects `terminal`/`shell` commands and blocks or escalates deploy commands. Every other tool call passes through untouched.
- Talos runs in-process as regular Python, like every Hermes plugin.

## Data and network (disclosure)

- **Stored:** findings JSON in Hermes's plugin data directory (`plugin_data_dir("talos")`, falling back to `$HERMES_HOME/plugin-data/talos/`). Nothing is written inside the plugin folder.
- **Sent anywhere:** nothing. Talos has no telemetry and calls no APIs of its own.
- **Local commands it runs:** `slither`, `sui move build --lint`, `solana config get`, `sui client active-env`, and `cast chain-id` to identify the network. `cast chain-id` contacts the RPC URL **you** configured for the deploy.
- **Credentials:** none read or stored.

## Fail-closed design

- If the gate errors or can't identify the network, the deploy is **blocked** (unknown network = mainnet).
- If an analyzer is missing, crashes, or a file can't be found, the code is reported as **UNCHECKED**, never as "no issues".
- Hermes itself blocks a gate hook that times out (30s default).

## Honest limits

- Talos is a guardrail, **not an audit.** The Anchor and Move rules are pattern-based heuristics; Slither covers EVM. Absence of findings is not proof of safety.
- Hermes does not run hooks in safe mode or for `ctx.dispatch_tool` calls from other plugins.
- Deploys through tools other than the terminal (e.g. a custom MCP deploy tool), or heavily obfuscated commands, are not detected.
- Some rules flag patterns rather than bugs (e.g. `init_if_needed`), so a correct fix may still show a medium finding needing approval.
- A network given only as an environment variable (`$RPC_URL`) is treated as mainnet.

## Development

```bash
hermes plugins validate .
python -c "from talos import scanner; print(scanner.scan_file('tests/fixtures/vuln_vault.rs'))"
```

Fixtures in `tests/fixtures/`: an Anchor vault, a Move token, a reentrancy bank in Solidity, and CPI safe/unsafe cases.

## License

MIT
