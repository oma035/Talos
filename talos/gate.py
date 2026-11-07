"""Talos deploy gate: detect deploys, resolve network, decide block / approve / allow."""
import os
import re
import shutil
import subprocess

from . import scanner, store

TEST_WORDS = ("localhost", "127.0.0.1", "0.0.0.0", "localnet", "anvil", "devnet", "testnet",
              "sepolia", "holesky", "hoodi", "goerli", "amoy", "mumbai", "fuji")
MAIN_WORDS = ("mainnet", "mainnet-beta")
TEST_CHAIN_IDS = {31337, 1337, 11155111, 17000, 560048, 84532, 421614, 11155420, 80002, 43113, 97}

# Warnings for allowed test-network deploys, attached to the command's result afterwards.
PENDING_WARNINGS = {}


def _flag(command, *names):
    for n in names:
        m = re.search(rf"{re.escape(n)}[=\s]+([^\s;&|]+)", command)
        if m:
            return m.group(1).strip("'\"")
    return None


def detect_deploy(command):
    c = " ".join((command or "").split())
    if re.search(r"\banchor\s+(deploy|upgrade)\b", c) or re.search(r"\bsolana\s+program\s+(deploy|upgrade)\b", c):
        return {"chain": "solana", "command": c,
                "hint": _flag(c, "--provider.cluster", "--url", "-u")}
    if re.search(r"\bsui\s+client\s+(publish|upgrade)\b", c):
        return {"chain": "sui", "command": c, "hint": None}
    if re.search(r"\bforge\s+script\b", c) and "--broadcast" in c:
        return {"chain": "evm", "command": c, "hint": _flag(c, "--rpc-url", "--fork-url", "--chain")}
    if re.search(r"\bforge\s+create\b", c):
        return {"chain": "evm", "command": c, "hint": _flag(c, "--rpc-url", "--chain")}
    if re.search(r"\bhardhat\s+(run|deploy|ignition\s+deploy)\b", c):
        return {"chain": "evm", "command": c, "hint": _flag(c, "--network")}
    return None


def _classify(value):
    v = (value or "").lower()
    if not v or v.startswith("$"):
        return "unknown"
    if any(w in v for w in TEST_WORDS):
        return "test"
    if any(w in v for w in MAIN_WORDS):
        return "mainnet"
    return "unknown"


def _run(cmd, cwd=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15, cwd=cwd).stdout
    except Exception:
        return ""


def resolve_network(deploy, project):
    """Return ('test'|'mainnet', label). Anything unclear counts as mainnet (fail closed)."""
    hint = deploy.get("hint")
    chain = deploy["chain"]
    if chain == "solana":
        if not hint:
            anchor_toml = os.path.join(project, "Anchor.toml")
            if os.path.exists(anchor_toml):
                m = re.search(r'cluster\s*=\s*"([^"]+)"', open(anchor_toml).read())
                hint = m.group(1) if m else None
        if not hint and shutil.which("solana"):
            m = re.search(r"RPC URL:\s*(\S+)", _run(["solana", "config", "get"]))
            hint = m.group(1) if m else None
    elif chain == "sui" and shutil.which("sui"):
        hint = _run(["sui", "client", "active-env"], cwd=project).strip()
    elif chain == "evm" and hint and hint.startswith("http") and shutil.which("cast"):
        out = _run(["cast", "chain-id", "--rpc-url", hint]).strip()
        if out.isdigit():
            return ("test" if int(out) in TEST_CHAIN_IDS else "mainnet", f"chain id {out}")
    kind = _classify(hint)
    return ("test" if kind == "test" else "mainnet", hint or "unknown network")


def find_project(start):
    for marker in ("Anchor.toml", "Move.toml", "foundry.toml", "hardhat.config.js", "hardhat.config.ts"):
        root = scanner._find_up(start, marker)
        if root:
            return root
    return start


def _approve_supported():
    try:
        import hermes_cli.plugins as p
        return hasattr(p, "resolve_pre_tool_block")
    except Exception:
        return False


def decide(deploy, cwd):
    project = find_project(cwd)
    findings = scanner.scan_path(project)          # always rescan at the gate
    store.set_findings(project, findings)
    network, label = resolve_network(deploy, project)
    worst = store.worst_severity(findings)
    report = store.format_findings(findings, header="Open findings")

    if network == "test":
        if findings:
            PENDING_WARNINGS[deploy["command"]] = (
                f"⚠️ [Talos] Deployed to {label} with {len(findings)} open finding(s). "
                f"These would BLOCK a mainnet deploy.\n{report}")
        return None

    if worst in ("critical", "high"):
        return {"action": "block", "message":
                f"🛡️ [Talos] Mainnet deploy BLOCKED ({label}). Fix these first, then retry:\n{report}"}
    if worst == "medium":
        msg = (f"🛡️ [Talos] Mainnet deploy ({label}) has medium-severity findings. "
               f"Approve only if you accept the risk:\n{report}")
        if _approve_supported():
            return {"action": "approve", "message": msg}
        return {"action": "block", "message": msg + "\n(This Hermes version can't ask for approval, so Talos blocked it.)"}
    return None
