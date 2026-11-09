"""Talos scanners: Slither (EVM), built-in Anchor rule pack, Sui Move lint + rules."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from . import store

SKIP_DIRS = {".git", "node_modules", "target", "out", "cache", "lib", "build", ".anchor"}
TIMEOUT = 180
SCANNER_VERSION = "2"          # bump to invalidate cached results when rules change

# Child processes get a minimal environment: never Hermes's provider keys or other secrets.
SAFE_ENV_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TERM",
                 "SOLC_VERSION", "VIRTUAL_ENV", "SUI_CONFIG_DIR")


def safe_env(extra_bin=None):
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    if extra_bin:
        env["PATH"] = extra_bin + os.pathsep + env.get("PATH", "")
    return env


def _remaining(deadline):
    return TIMEOUT if deadline is None else deadline - time.monotonic()


def _out_of_time(target, tool):
    return [_finding(target, None, "high", "scanner-timeout",
                     "Talos ran out of time before scanning this file, so it is UNCHECKED. "
                     "Run /talos (no time limit), then retry.", tool)]


def _digest(*paths):
    h = hashlib.sha256(SCANNER_VERSION.encode())
    for p in sorted(paths):
        h.update(p.encode())
        try:
            with open(p, "rb") as fh:
                h.update(fh.read())
        except OSError:
            h.update(b"<missing>")
    return h.hexdigest()


UNCACHEABLE = {"scanner-missing", "scanner-error", "scanner-timeout"}


def _cached(key_path, files, scan):
    """Reuse findings when the scanned files are byte-identical to the last scan."""
    digest = _digest(*files)
    hit = store.cache_get(key_path, digest)
    if hit is not None:
        return hit
    findings = scan()
    if not any(f.get("rule") in UNCACHEABLE for f in findings):
        store.cache_put(key_path, digest, findings)
    return findings


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
def scan_path(path, deadline=None):
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isfile(path):
        return scan_file(path, deadline)
    findings = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith((".sol", ".rs", ".move")):
                findings += scan_file(os.path.join(root, name), deadline)
    move_pkg = _find_up(path, "Move.toml") or (path if os.path.exists(os.path.join(path, "Move.toml")) else None)
    if move_pkg:
        findings += scan_move_lint(move_pkg, deadline)
    return findings


def scan_file(path, deadline=None):
    path = os.path.abspath(path)
    if path.endswith(".sol"):
        return _cached(path, [path], lambda: scan_solidity(path, deadline))
    if path.endswith(".rs"):
        return _cached(path, [path], lambda: scan_anchor_file(path))
    if path.endswith(".move"):
        return _cached(path, [path], lambda: scan_move_rules(path))
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
    found = shutil.which("slither")
    if found:
        return found
    cand = os.path.join(os.path.dirname(sys.executable), "slither")
    return cand if os.path.isfile(cand) else None


def _remaps(root):
    """Import remappings read from static files only. Never runs the project's tooling."""
    maps = {}
    rt = os.path.join(root, "remappings.txt")
    if os.path.isfile(rt):
        for line in open(rt, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.split(":", 1)[-1]
            maps[k] = v if os.path.isabs(v) else os.path.join(root, v)
    nm = os.path.join(root, "node_modules")
    if os.path.isdir(nm):
        for d in os.listdir(nm):
            if d.startswith("@") and os.path.isdir(os.path.join(nm, d)):
                maps.setdefault(d + "/", os.path.join(nm, d) + "/")
    lib = os.path.join(root, "lib")
    if os.path.isdir(lib) and not os.path.isfile(rt):
        for d in os.listdir(lib):
            src = os.path.join(lib, d, "src")
            if os.path.isdir(src):
                maps.setdefault(d + "/", src + "/")
    # slither splits remaps on spaces; skip any path that contains one
    return [f"{k}={v}" for k, v in maps.items() if " " not in k + v]


def scan_solidity(target, deadline=None):
    """Slither on ONE file, compiled with plain solc. Never invokes Hardhat/Foundry, never loads the
    repo's slither config, and runs from an empty temp dir with a minimal environment, so scanning
    a cloned repo can't execute that repo's code."""
    slither = _slither_bin()
    if not slither:
        return [_finding(target, None, "high", "scanner-missing",
                         "Slither is not installed, so Solidity code is unchecked. Run: pip install slither-analyzer",
                         "talos")]
    budget = _remaining(deadline)
    if budget < 2:
        return _out_of_time(target, "slither")
    root = (_find_up(target, "foundry.toml") or _find_up(target, "hardhat.config.js")
            or _find_up(target, "hardhat.config.ts") or os.path.dirname(target))
    cmd = [slither, target, "--compile-force-framework", "solc", "--json", "-"]
    maps = _remaps(root)
    if maps:
        cmd += ["--solc-remaps", " ".join(maps)]
    try:
        with tempfile.TemporaryDirectory(prefix="talos-") as work:
            with open(os.path.join(work, "slither.config.json"), "w") as fh:
                fh.write("{}")                    # shadows any config the repo ships
            proc = subprocess.run(cmd, env=safe_env(os.path.dirname(slither)), capture_output=True,
                                  text=True, timeout=min(TIMEOUT, budget), cwd=work)
        data = json.loads(proc.stdout or "{}")
        if not data.get("success") or "results" not in data:
            err = (data.get("error") or proc.stderr or "no output").strip()
            return [_finding(target, None, "high", "scanner-error",
                             "Slither could not analyze this code, so it is UNCHECKED: " + err[-300:], "slither")]
    except subprocess.TimeoutExpired:
        return _out_of_time(target, "slither")
    except Exception as exc:
        return [_finding(target, None, "high", "scanner-error", f"Slither failed: {exc}", "slither")]
    project = os.path.dirname(target)
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


def scan_move_lint(package_dir, deadline=None):
    if not shutil.which("sui"):
        return []
    files = [os.path.join(package_dir, "Move.toml")]
    for root, dirs, names in os.walk(package_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        files += [os.path.join(root, n) for n in names if n.endswith(".move")]
    return _cached(package_dir + os.sep + "<sui-lint>", files, lambda: _move_lint(package_dir, deadline))


def _move_lint(package_dir, deadline):
    budget = _remaining(deadline)
    if budget < 2:
        return _out_of_time(package_dir, "sui-lint")
    try:
        proc = subprocess.run(["sui", "move", "build", "--lint"], capture_output=True, text=True,
                              timeout=min(TIMEOUT, budget), cwd=package_dir, env=safe_env())
    except subprocess.TimeoutExpired:
        return _out_of_time(package_dir, "sui-lint")
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
