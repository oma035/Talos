"""Talos findings store: remembers open security findings per file."""
import json
import os
import threading

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_LOCK = threading.Lock()


def _data_dir():
    """Plugin runtime data lives outside the plugin folder (catalog rule)."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # Hermes helper, if available
        path = str(plugin_data_dir("talos"))
    except Exception:
        home = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
        path = os.path.join(home, "plugin-data", "talos")
    os.makedirs(path, exist_ok=True)
    return path


def _db_path():
    return os.path.join(_data_dir(), "findings.json")


def _load():
    try:
        with open(_db_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save(data):
    tmp = _db_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, _db_path())


def _norm(path):
    return os.path.abspath(os.path.expanduser(path))


def set_findings(scanned_path, findings):
    """Replace stored findings for everything under scanned_path with a fresh scan."""
    root = _norm(scanned_path)
    with _LOCK:
        data = _load()
        # Drop old entries for files inside the scanned path (they were rescanned).
        for key in list(data.keys()):
            if key == root or key.startswith(root + os.sep):
                del data[key]
        for f in findings:
            key = _norm(f.get("file") or root)
            data.setdefault(key, []).append(f)
        _save(data)


def all_findings(under=None):
    data = _load()
    out = []
    root = _norm(under) if under else None
    for key, items in data.items():
        if root and not (key == root or key.startswith(root + os.sep)):
            continue
        out.extend(items)
    return out


def open_findings(min_severity="low", under=None):
    floor = SEVERITY_ORDER.get(min_severity, 1)
    return [
        f for f in all_findings(under)
        if SEVERITY_ORDER.get(f.get("severity", "info"), 0) >= floor
    ]


def worst_severity(findings):
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 0))["severity"]


def format_findings(findings, header="Talos findings"):
    if not findings:
        return f"{header}: no issues found ✅"
    ranked = sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.get("severity", "info"), 0))
    lines = [f"{header} ({len(findings)}):"]
    for f in ranked:
        loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
        lines.append(f"- {f.get('severity', 'info').upper()} {loc} [{f.get('rule', '?')}] {f.get('message', '')}")
    return "\n".join(lines)


def format_report(path, findings):
    counts = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    summary = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))) or "none"
    return (
        f"🛡 Talos audit report for {path}\n"
        f"Summary: {summary}\n\n"
        f"{format_findings(findings, header='Findings')}"
    )
