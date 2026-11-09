"""Talos deploy gate: detect deploys, resolve network, decide block / approve / allow."""
import os
import re
import shutil
import subprocess
import time

from . import scanner, store

GATE_BUDGET = 20.0   # seconds; Hermes's pre_tool_call hook limit is 30 s and fails closed

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


SCRIPT_EXTS = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts")
PKG_RUN = re.compile(r"\b(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([\w:.-]+)")
MAX_SCRIPT_BYTES = 200_000


def detect_deploy(command, cwd=None, _depth=0):
    """Direct deploy commands, plus deploys hidden inside scripts the command runs."""
    import os
    c = " ".join((command or "").split())
    hit = _detect_direct(c)
    if hit or _depth >= 3:
        return hit
    cwd = cwd or os.getcwd()
    for body, via in _referenced_scripts(c, cwd):
        body = body.replace("\\\n", " ")
        for line in body.splitlines():
            line = re.sub(r"[\"'`,\[\]()]", " ", line)
            inner = detect_deploy(line, cwd, _depth + 1)
            if inner:
                return {**inner, "command": c, "via": via}
    return None


def _read_text(path):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_SCRIPT_BYTES)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _referenced_scripts(c, cwd):
    import json, os
    out = []
    for tok in re.split(r"[\s;&|()<>]+", c):
        tok = tok.strip("'\"")
        if not tok or tok.startswith("-"):
            continue
        p = os.path.expanduser(tok)
        p = p if os.path.isabs(p) else os.path.join(cwd, p)
        if not os.path.isfile(p):
            continue
        body = _read_text(p)
        if body is None:
            continue
        if p.endswith(SCRIPT_EXTS) or body.startswith("#!"):
            out.append((body, os.path.relpath(p, cwd)))
    names = [m.group(1) for m in PKG_RUN.finditer(c)]
    if names:
        pkg = scanner._find_up(cwd, "package.json")
        if pkg:
            try:
                scripts = json.loads(_read_text(os.path.join(pkg, "package.json")) or "{}").get("scripts", {})
            except Exception:
                scripts = {}
            for n in names:
                if n in scripts:
                    out.append((scripts[n], f"package.json:{n}"))
    if re.search(r"\b(make|just)\b", c):
        for mf in ("Makefile", "makefile", "GNUmakefile", "justfile", "Justfile"):
            body = _read_text(os.path.join(cwd, mf))
            if body:
                out.append((body, mf))
    return out


def _detect_direct(command):
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
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5, cwd=cwd,
                              env=scanner.safe_env()).stdout
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
    # Approval escalation ships in Hermes >=0.18.1, enforced via requires_hermes in plugin.yaml.
    return True


def _rule_key(project, findings):
    """Approval grain: one project + its exact open findings. New findings need a new approval."""
    import hashlib
    sig = "|".join(sorted(f"{f.get('rule')}:{f.get('file')}" for f in findings))
    return "talos:" + hashlib.sha256(f"{project}|{sig}".encode()).hexdigest()[:16]


def decide(deploy, cwd):
    project = find_project(cwd)
    network, label = resolve_network(deploy, project)     # cheap, and decides how much work to do

    if network == "test":                                  # never slow down test deploys
        findings = store.all_findings(under=project)
        if findings:
            report = store.format_findings(findings, header="Open findings")
            PENDING_WARNINGS[deploy["command"]] = (
                f"⚠ [Talos] Deployed to {label} with {len(findings)} open finding(s). "
                f"These would BLOCK a mainnet deploy.\n{report}")
        return None

    # Mainnet: rescan, but unchanged files come from the cache, inside a hard time budget.
    findings = scanner.scan_path(project, deadline=time.monotonic() + GATE_BUDGET)
    store.set_findings(project, findings)
    worst = store.worst_severity(findings)
    report = store.format_findings(findings, header="Open findings")

    if worst in ("critical", "high"):
        return {"action": "block", "message":
                f"🛡 [Talos] Mainnet deploy BLOCKED ({label}). Fix these first, then retry:\n{report}"}
    if worst == "medium":
        msg = (f"🛡 [Talos] Mainnet deploy ({label}) has medium-severity findings. "
               f"Approve only if you accept the risk:\n{report}")
        if _approve_supported():
            return {"action": "approve", "rule_key": _rule_key(project, findings), "message": msg}
        return {"action": "block", "message": msg + "\n(This Hermes version can't ask for approval, so Talos blocked it.)"}
    return None
