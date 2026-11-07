"""Talos: automatic, unskippable smart-contract security checks for Hermes Agent."""
import json
import os

from .talos import gate, scanner, store

CONTRACT_EXTS = (".sol", ".rs", ".move")
WRITE_TOOLS = {"write_file", "patch", "edit_file", "write", "str_replace_editor"}
TERMINAL_TOOLS = {"terminal", "shell", "bash"}

TALOS_SCAN_SCHEMA = {
    "name": "talos_scan",
    "description": "Scan a smart-contract file or project folder (Solidity, Anchor, Sui Move) for security issues.",
    "parameters": {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "File or project folder to scan"}},
        "required": ["path"],
    },
}


def _path_from_args(args):
    if isinstance(args, dict):
        for key in ("path", "file_path", "filename", "file", "target_file"):
            if isinstance(args.get(key), str):
                return args[key]
    return None


def _command_from_args(args):
    if isinstance(args, dict):
        for key in ("command", "cmd", "script"):
            if isinstance(args.get(key), str):
                return args[key]
    return ""


def _cwd_from_args(args):
    if isinstance(args, dict):
        for key in ("workdir", "cwd", "working_directory"):
            if isinstance(args.get(key), str):
                return args[key]
    return os.getcwd()


# ------------------------------------------------------------ hooks
def on_tool_result(**kwargs):
    """1) After a contract file is written, scan it and show findings to Hermes immediately.
       2) After an allowed test-network deploy, attach the warning."""
    try:
        tool, args, result = kwargs.get("tool_name"), kwargs.get("args"), kwargs.get("result", "")
        if tool in TERMINAL_TOOLS:
            cmd = " ".join(_command_from_args(args).split())
            warning = gate.PENDING_WARNINGS.pop(cmd, None)
            return f"{result}\n\n{warning}" if warning else None
        if tool not in WRITE_TOOLS:
            return None
        path = _path_from_args(args)
        if not path or not path.endswith(CONTRACT_EXTS):
            return None
        findings = scanner.scan_path(path)
        store.set_findings(path, findings)
        note = store.format_findings(findings, header=f"[Talos] Security scan of {os.path.basename(path)}")
        if findings:
            note += "\nFix the high/critical issues above before deploying. Talos will block mainnet deploys until they're resolved."
        return f"{result}\n\n{note}"
    except Exception as exc:
        return f"{kwargs.get('result', '')}\n\n[Talos] scan error: {exc}"


def on_pre_llm(**kwargs):
    """Before each turn, remind Hermes of open medium+ findings so it fixes them unprompted."""
    try:
        items = store.open_findings(min_severity="medium", under=os.getcwd())
        if not items:
            return None
        return {"context": store.format_findings(
            items, header="[Talos] Open smart-contract security findings in this project. Fix these")}
    except Exception:
        return None


def on_pre_tool(**kwargs):
    """Deploy gate. Fails CLOSED: if Talos errors on a deploy, the deploy is blocked."""
    try:
        if kwargs.get("tool_name") not in TERMINAL_TOOLS:
            return None
        args = kwargs.get("args") or {}
        deploy = gate.detect_deploy(_command_from_args(args))
        if not deploy:
            return None
        return gate.decide(deploy, _cwd_from_args(args))
    except Exception as exc:
        return {"action": "block", "message": f"🛡️ [Talos] Gate error, deploy blocked to be safe: {exc}"}


# ------------------------------------------------------------ tool + command
def talos_scan(args, **kwargs):
    try:
        path = (args or {}).get("path") or os.getcwd()
        findings = scanner.scan_path(path)
        store.set_findings(path, findings)
        return json.dumps({"path": path, "count": len(findings), "findings": findings})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def talos_command(raw_args=""):
    try:
        path = (raw_args or "").strip() or os.getcwd()
        project = gate.find_project(os.path.abspath(os.path.expanduser(path)))
        findings = scanner.scan_path(project)
        store.set_findings(project, findings)
        return store.format_report(project, findings)
    except Exception as exc:
        return f"[Talos] report error: {exc}"


def register(ctx):
    ctx.register_tool(name="talos_scan", toolset="talos", schema=TALOS_SCAN_SCHEMA, handler=talos_scan)
    ctx.register_hook("transform_tool_result", on_tool_result)
    ctx.register_hook("pre_llm_call", on_pre_llm)
    ctx.register_hook("pre_tool_call", on_pre_tool)
    ctx.register_command("talos", talos_command, description="Full smart-contract security report for this project")
