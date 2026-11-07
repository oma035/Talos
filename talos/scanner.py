"""Talos scanners: Slither (EVM), built-in Anchor rule pack, Sui Move lint + rules."""
import json
import os
import re
import shutil
import subprocess

SKIP_DIRS = {".git", "node_modules", "target", "out", "cache", "lib", "build", ".anchor"}
TIMEOUT = 180


def _finding(file, line, severity, rule, message, tool):
    return {
        "file": os.path.abspath(file) if file else None,
        "line": line,
        "severity": severity,
        "rule": rule,
        "message": message,
        "tool": tool,
    }


def _line_of(text, index):
    return text.count("\n", 0, index) + 1


# ---------------------------------------------------------------- dispatch
def scan_path(path):
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isfile(path):
        return scan_file(path)
    findings = []
    sol_done = False
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = os.path.join(root, name)
            if name.endswith(".sol"):
                if not sol_done:
                    findings += scan_solidity(path)  # Slither scans the whole project once
                    sol_done = True
            elif name.endswith(".rs"):
                findings += scan_anchor_file(full)
            elif name.endswith(".move"):
                findings += scan_move_rules(full)
    move_pkg = _find_up(path, "Move.toml") or (path if os.path.exists(os.path.join(path, "Move.toml")) else None)
    if move_pkg:
        findings += scan_move_lint(move_pkg)
    return findings


def scan_file(path):
    if path.endswith(".sol"):
        return scan_solidity(path)
    if path.endswith(".rs"):
        return scan_anchor_file(path)
    if path.endswith(".move"):
        return scan_move_rules(path)
    return []


def _find_up(start, marker):
    cur = start if os.path.isdir(start) else os.path.dirname(start)
    while True:
        if os.path.exists(os.path.join(cur, marker)):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


# ---------------------------------------------------------------- EVM / Slither
SLITHER_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low",
                    "Informational": "info", "Optimization": "info"}


def _slither_bin():
    """Find slither on PATH, or next to the Python running Hermes (its venv bin)."""
    import os, sys
    found = shutil.which("slither")
    if found:
        return found
    cand = os.path.join(os.path.dirname(sys.executable), "slither")
    return cand if os.path.isfile(cand) else None


def _tool_env(binpath):
    import os
    env = dict(os.environ)
    env["PATH"] = os.path.dirname(binpath) + os.pathsep + env.get("PATH", "")
    return env


def scan_solidity(target):
    slither = _slither_bin()
    if not slither:
        return [_finding(target, None, "high", "scanner-missing",
                         "Slither is not installed, so Solidity code is unchecked. Run: pip install slither-analyzer",
                         "talos")]
    project = _find_up(target, "foundry.toml") or _find_up(target, "hardhat.config.js") \
        or _find_up(target, "hardhat.config.ts") or target
    try:
        proc = subprocess.run([slither, project, "--json", "-"], env=_tool_env(slither), capture_output=True,
                              text=True, timeout=TIMEOUT, cwd=project if os.path.isdir(project) else None)
        data = json.loads(proc.stdout or "{}")
    except subprocess.TimeoutExpired:
        return [_finding(target, None, "high", "scanner-timeout", "Slither timed out", "slither")]
    except Exception as exc:
        return [_finding(target, None, "high", "scanner-error", f"Slither failed: {exc}", "slither")]
    out = []
    for det in (data.get("results") or {}).get("detectors", []):
        line, file = None, target
        for el in det.get("elements", []):
            sm = el.get("source_mapping") or {}
            if sm.get("lines"):
                line = sm["lines"][0]
                rel = sm.get("filename_absolute") or sm.get("filename_relative")
                if rel:
                    file = rel if os.path.isabs(rel) else os.path.join(project if os.path.isdir(project) else os.path.dirname(project), rel)
                break
        out.append(_finding(file, line, SLITHER_SEVERITY.get(det.get("impact"), "info"),
                            det.get("check", "slither"),
                            (det.get("description") or "").strip().split("\n")[0], "slither"))
    return out


# ---------------------------------------------------------------- Solana / Anchor rule pack
ACCOUNTS_STRUCT = re.compile(r"#\[derive\([^)]*Accounts[^)]*\)\]\s*pub\s+struct\s+\w+[^{]*\{(?P<body>.*?)\n\}", re.S)
FIELD = re.compile(r"(?P<attrs>(?:\s*(?:///[^\n]*|#\[account\((?:[^()]|\([^()]*\))*\)\]))*)\s*pub\s+(?P<name>\w+)\s*:\s*(?P<ty>[^,\n]+),", re.S)
AUTH_NAMES = re.compile(r"^(authority|owner|admin|signer|payer|user|creator|manager|operator)$")
RAW_TYPES = ("AccountInfo<", "UncheckedAccount<")
MONEY_NAMES = r"(amount|balance|lamports|supply|total|reward|shares|deposit|stake)"


def scan_anchor_file(path):
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return []
    if "anchor_lang" not in text and "solana_program" not in text and "#[derive(Accounts" not in text:
        return []
    out = []
    for struct in ACCOUNTS_STRUCT.finditer(text):
        body, base = struct.group("body"), struct.start("body")
        for field in FIELD.finditer(body):
            attrs, name, ty = field.group("attrs"), field.group("name"), field.group("ty").strip()
            line = _line_of(text, base + field.start("name"))
            is_raw = any(t in ty for t in RAW_TYPES)
            has_constraint = bool(re.search(r"(signer|owner\s*=|address\s*=|seeds\s*=|has_one|constraint\s*=)", attrs))
            if AUTH_NAMES.match(name) and "Signer<" not in ty and "signer" not in attrs:
                if is_raw or "Account<" in ty:
                    out.append(_finding(path, line, "critical", "missing-signer-check",
                                        f"`{name}` looks like an authority but is not a Signer. Anyone can pass any account here. Use Signer<'info>.",
                                        "talos-anchor"))
            if is_raw and not has_constraint:
                sev = "low" if "/// CHECK:" in attrs else "high"
                out.append(_finding(path, line, sev, "unchecked-account",
                                    f"`{name}` is {ty.split('<')[0]} with no owner/address/seeds constraint. Validate it or use a typed Account<'info, T>.",
                                    "talos-anchor"))
            if "seeds" in attrs and "bump" not in attrs:
                out.append(_finding(path, line, "medium", "pda-missing-bump",
                                    f"`{name}` uses PDA seeds without a `bump` constraint. Add `bump` so the canonical PDA is enforced.",
                                    "talos-anchor"))
            if "init_if_needed" in attrs:
                out.append(_finding(path, line, "medium", "reinitialization-risk",
                                    f"`{name}` uses init_if_needed. Make sure existing state cannot be reset by a second call.",
                                    "talos-anchor"))
            if re.search(r"Program<", ty) is None and re.search(r"program$", name) and is_raw:
                out.append(_finding(path, line, "high", "arbitrary-cpi-program",
                                    f"`{name}` is a raw account used as a program. Use Program<'info, T> so the program ID is checked.",
                                    "talos-anchor"))
    for m in re.finditer(r"\b\w*" + MONEY_NAMES + r"\w*\s*(\+=|-=|\*=)", text):
        out.append(_finding(path, _line_of(text, m.start()), "medium", "unchecked-arithmetic",
                            "Unchecked arithmetic on a balance-like value. Use checked_add / checked_sub / checked_mul.",
                            "talos-anchor"))
    for m in re.finditer(r"\binvoke(_signed)?\s*\(", text):
        window = text[max(0, m.start() - 600):m.start() + 300]
        # Instructions from native builders hardcode the program ID, so the CPI target can't be swapped.
        if re.search(r"(system_instruction::|spl_token(_2022)?::instruction::|spl_associated_token_account::instruction::|system_program::ID)", window):
            continue
        # Only an actual comparison counts as a check; merely naming program_id does not.
        if not re.search(r"(program_id\s*[!=]=|[!=]=\s*[\w:.&*()]*program_id|\bkey\(?\)?\s*[!=]=|require_keys_eq!|check_id\s*\()", window[:600]):
            out.append(_finding(path, _line_of(text, m.start()), "high", "unchecked-cpi",
                                "Cross-program invoke without an obvious program ID check before it.",
                                "talos-anchor"))
    return out


# ---------------------------------------------------------------- Sui / Move
PRIVILEGED = re.compile(r"public\s+(entry\s+)?fun\s+(mint\w*|burn\w*|withdraw\w*|set_\w+|admin\w*|pause\w*|upgrade\w*)\s*(<[^>]*>)?\s*\((?P<params>[^)]*)\)", re.S)


def scan_move_rules(path):
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return []
    out = []
    for m in PRIVILEGED.finditer(text):
        if not re.search(r"(Cap\b|Cap<|AdminCap|OwnerCap|TreasuryCap|UpgradeCap|Publisher)", m.group("params")):
            out.append(_finding(path, _line_of(text, m.start()), "high", "missing-capability-check",
                                f"Privileged function `{m.group(2)}` takes no capability object, so anyone may be able to call it.",
                                "talos-move"))
    return out


LINT_LOC = re.compile(r"┌─\s*(?P<file>[^:\s]+\.move):(?P<line>\d+)")


def scan_move_lint(package_dir):
    if not shutil.which("sui"):
        return []
    try:
        proc = subprocess.run(["sui", "move", "build", "--lint"], capture_output=True, text=True,
                              timeout=TIMEOUT, cwd=package_dir)
    except Exception as exc:
        return [_finding(package_dir, None, "medium", "scanner-error", f"sui move lint failed: {exc}", "sui-lint")]
    out, current = [], None
    for raw in (proc.stdout + "\n" + proc.stderr).splitlines():
        line = raw.strip()
        if line.startswith(("warning", "error")):
            current = line
        loc = LINT_LOC.search(raw)
        if loc and current:
            sev = "high" if current.startswith("error") else "medium"
            out.append(_finding(os.path.join(package_dir, loc.group("file")), int(loc.group("line")), sev,
                                "sui-lint", current, "sui-lint"))
            current = None
    return out
