"""
Attestation Guardrails Plugin — intercept dangerous commands and file
operations, request attestation approval via xChk, and block until approved.

Uses Hermes' built-in dangerous command detection (from tools.approval)
to decide what needs attestation — the same ~50 patterns Hermes' own
terminal tool uses for approval gating. Also guards write_file/patch on
sensitive paths.

Effective UID tracking: every terminal command is wrapped with a
post-execution UID check. If the UID changes after a command runs
(e.g. privilege escalation via sudo su, pkexec, CVE exploit), the
plugin screams and creates an attestation — even if the command itself
isn't in the dangerous patterns list.

Set XCHK_BLOCK_ALL=true to revert to blocking EVERYTHING (legacy mode).
Set XCHK_SKIP_UID_CHECK=true to disable UID tracking.
"""

import json
import logging
import os
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CONTEXT = None

logger = logging.getLogger(__name__)

CALLBACKS_LOG = "/tmp/CALLBACKS"
XCHK_BASE = "https://in.xchk.io"

# ── Mode ────────────────────────────────────────────────────────────────
# BLOCK_ALL=true → every tool call requires attestation (legacy jam-mode)
# BLOCK_ALL=false (default) → only commands/files matching Hermes' dangerous
#   patterns require attestation. Safe commands pass through.
BLOCK_ALL = os.environ.get("XCHK_BLOCK_ALL", "false").lower() in ("1", "true", "yes")

# ── Effective UID Tracking ─────────────────────────────────────────────
# Capture the expected UID at plugin load time. If a terminal command
# changes the effective UID (privilege escalation), we scream.
_EXPECTED_UID = os.getuid()
_EXPECTED_USER = os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"
_UID_CHECK_ENABLED = not os.environ.get("XCHK_SKIP_UID_CHECK", "").lower() in ("1", "true", "yes")
_UID_MARKER = "__XCHK_UID__"  # unique sentinel injected into command output
_UID_MARKER_RE = re.compile(r'\n?' + re.escape(_UID_MARKER) + r':(\d+):([^\s]+)__')

# Attestation TTL — how long the approver has to respond.
# Increased to 10 minutes to allow for multi-level escalation.
ATTESTATION_TTL_SECONDS = 10 * 60  # 10 minutes

# Poll timeout — must outwait server TTL plus escalation time
POLL_TIMEOUT = ATTESTATION_TTL_SECONDS + 60

# Resources that require attestation
#
# Each resource can define levels for the approval policy:
#   levels: [
#     { role: "...", n: N, preferred: [...], members: [...], autoEscalate: bool },
#     ...
#   ]
#
# Each level is sequential — level N only fires after level N-1 is satisfied.
# autoEscalate: if the level's N approvals can't be obtained within TTL, move
# to next level (default true on the server side).
#
# When levels is set, the attestation goes to those approvers — NOT the owner.
# The owner field is used as a fallback label only.
RESOURCES = [
    {
        "host": "starshout.net",
        "owner": "sean@maclawran.ca",
        "rules": {
            "destructive": True,
        },
        # Two-level escalation:
        #   1) 1 approver — prefer owner, escalate to the pool on timeout
        #   2) managers — bbunix@yahoo.com + bbunix@gmail.com, any 1 of them
        "levels": [
            {
                "role": "approver",
                "n": 1,
                "preferred": ["sean@maclawran.ca"],
                "members": ["sean@maclawran.ca", "bbunix@yahoo.com", "bbunix@gmail.com"],
                "autoEscalate": True,
            },
            {
                "role": "manager",
                "n": 1,
                "members": ["bbunix@yahoo.com", "bbunix@gmail.com"],
                "autoEscalate": False,
            },
        ],
    }
]

# Tools that we NEVER attestate — these are fundamental infrastructure
# that, if blocked, would prevent the approval flow from working.
ALWAYS_ALLOW_TOOLS = set()

# Tool categories for the prompt — helps the approver understand context
_TOOL_LABELS = {
    "terminal": "Shell Command",
    "read_file": "Read File",
    "write_file": "Write File",
    "patch": "Edit File",
    "search_files": "Search Files",
    "web_search": "Web Search",
    "web_extract": "Web Extract",
    "browser_navigate": "Browse URL",
    "browser_click": "Browser Click",
    "browser_type": "Browser Type Input",
    "browser_snapshot": "Browser Snapshot",
    "browser_scroll": "Browser Scroll",
    "execute_code": "Execute Python Code",
    "vision_analyze": "Analyze Image",
    "image_generate": "Generate Image",
    "text_to_speech": "Text to Speech",
    "delegate_task": "Delegate Task to Sub-Agent",
    "skill_view": "View Skill",
    "memory": "Memory Operation",
    "wx_conditions": "Weather Check",
    "wx_forecast": "Weather Forecast",
    "wx_alerts": "Weather Alerts",
    "wx_severe": "Severe Weather Check",
    "wx_sounding": "Atmospheric Sounding",
    "wx_metar": "METAR Observation",
    "wx_brief": "Weather Briefing",
    "wx_calc": "Weather Calculation",
    "wx_global": "Global Weather",
    "clarify": "Ask User Question",
    "honcho_profile": "User Profile Lookup",
    "honcho_search": "Memory Search",
    "honcho_reasoning": "Memory Reasoning",
    "honcho_context": "Session Context",
    "honcho_conclude": "Save Conclusion",
}

# Skip these in the prompt for brevity — they're noise
_BRIEF_TOOLS = {
    "browser_snapshot", "browser_scroll", "browser_get_images",
    "browser_back", "browser_console",
}

# ── Sensitive file write paths ──────────────────────────────────────────
# Mirrors the key targets from Hermes' tools.approval._SENSITIVE_WRITE_TARGET
# so write_file/patch to these paths triggers attestation.
_SENSITIVE_WRITE_TARGETS = re.compile(
    r"(?:"
    r"~/\.ssh/|"
    r"~/\.bashrc|~/\.zshrc|~/\.profile|~/\.bash_profile|~/\.zprofile|"
    r"~/\.netrc|~/\.pgpass|~/\.npmrc|~/\.pypirc|"
    r"~/\.hermes/config\.yaml|~/\.hermes/\.env|"
    r"/etc/|/private/etc/|"
    r"/dev/sd"
    r")",
    re.IGNORECASE,
)

# Project-relative sensitive paths
_PROJECT_SENSITIVE_WRITE_TARGETS = re.compile(
    r"(?:^|/)\.env(?:\.[a-zA-Z0-9]+)?$|"
    r"(?:^|/)config\.yaml$",
)


def _log_call(kind: str, **kwargs):
    """Append a JSON line to the CALLBACKS log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "kind": kind,
    }
    clean = {}
    for k, v in kwargs.items():
        try:
            json.dumps({k: v})
            clean[k] = v
        except (TypeError, ValueError):
            clean[k] = f"<non-serializable: {type(v).__name__}>"
    entry["payload"] = clean
    try:
        with open(CALLBACKS_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.warning("Failed to write to %s: %s", CALLBACKS_LOG, exc)


def _get_api_key() -> Optional[str]:
    """Read xChk API key from env."""
    return os.environ.get("XCHK_API_KEY") or os.environ.get("xchk_api_key")


def _is_ssh_to_host(command: str, host: str) -> bool:
    """Check if a shell command is an SSH to the given host."""
    cmd = command.strip()
    m = re.match(r'^ssh\s+', cmd)
    if not m:
        return False
    parts = cmd.split()
    for i, part in enumerate(parts[1:], 1):
        if part.startswith("-"):
            continue
        if "@" in part:
            target = part.split("@")[1]
        else:
            target = part
        if target == host or target.endswith("." + host):
            return True
        break
    return False


def _extract_remote_command(command: str) -> str:
    """Extract the command run remotely via SSH (after ssh user@host)."""
    parts = command.strip().split()
    after_host = False
    for part in parts:
        if after_host:
            return part
        if part.startswith("-"):
            continue
        if "@" in part or not part.startswith("ssh"):
            after_host = True
    return ""


def _is_command_dangerous(command: str) -> tuple:
    """Check a command against Hermes' dangerous command detector.

    Returns:
        (is_dangerous, description) or (False, None)
    """
    try:
        from tools.approval import detect_dangerous_command, detect_hardline_command

        # Check hardline first (unconditional blocks)
        is_hardline, h_desc = detect_hardline_command(command)
        if is_hardline:
            return (True, f"HARDLINE: {h_desc}")

        # Then check dangerous patterns
        is_dangerous, pattern_key, desc = detect_dangerous_command(command)
        if is_dangerous:
            return (True, desc)

    except ImportError:
        logger.warning("tools.approval not available — skipping command detection")
    except Exception as exc:
        logger.warning("Command detection failed: %s", exc)

    return (False, None)


def _is_sensitive_write(path: str) -> bool:
    """Check if a file path is a sensitive write target."""
    expanded = os.path.expanduser(path)
    if _SENSITIVE_WRITE_TARGETS.search(expanded):
        return True
    if _PROJECT_SENSITIVE_WRITE_TARGETS.search(path):
        return True
    return False


# ── Effective UID Tracking ──────────────────────────────────────────────
# Tracks UID before/after every terminal command to catch privilege
# escalation that doesn't match our pattern list (zero-day exploits,
# unusual escalation tools, etc.).


def _wrap_with_uid_check(command: str) -> str:
    """Wrap a terminal command with a post-execution UID probe.

    Injects a unique sentinel after the command so we can detect if the
    effective UID changed — evidence of privilege escalation.
    """
    if not _UID_CHECK_ENABLED:
        return command
    # Use a subshell to capture the UID after the command runs.
    # Format: __XCHK_UID__:<uid>:<username>__
    sentinel = f'echo {_UID_MARKER}:$(id -u):$(whoami)__'
    # Chain via ; so the sentinel runs regardless of exit code.
    # Wrap in a subshell to handle multi-command chains properly.
    return f'( {command} ); {sentinel}'


def _check_uid_change(output: str, command: str) -> Optional[str]:
    """Check if a terminal command's output shows a UID change.

    Returns a danger description string if UID changed, None if safe.
    """
    if not _UID_CHECK_ENABLED:
        return None
    if not output:
        return None

    m = _UID_MARKER_RE.search(output)
    if not m:
        # Sentinel not found — could be output truncated or a very short
        # command. Don't false-positive on this.
        return None

    # Use the LAST match — the injected sentinel is always last in the
    # output, and taking the last prevents LLM-generated fake sentinels
    # from masking the real UID check.
    all_matches = list(_UID_MARKER_RE.finditer(output))
    if all_matches:
        m = all_matches[-1]

    actual_uid = int(m.group(1))
    actual_user = m.group(2)

    if actual_uid != _EXPECTED_UID:
        return (
            f"🚨 PRIVILEGE ESCALATION DETECTED 🚨\n"
            f"Expected UID {_EXPECTED_UID} ({_EXPECTED_USER}), "
            f"but after this command the effective UID is {actual_uid} ({actual_user}).\n"
            f"This means the command escalated privileges — possibly via an exploit\n"
            f"or an unusual escalation path not in our pattern list.\n"
            f"Command: `{command[:300]}`"
        )

    return None


def _strip_uid_marker(output: str) -> str:
    """Remove ALL UID sentinel lines from the output before returning it."""
    if not _UID_CHECK_ENABLED or not output:
        return output
    return _UID_MARKER_RE.sub('', output).rstrip('\n')


def _create_attestation(prompt: str, target_email: str, levels: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """Create an attestation via the xChk API. Returns attId or None.

    Args:
        prompt: Description of what needs approval.
        target_email: Primary target user (owner).
        levels: Optional policy levels. When provided, the attestation routes
            to these approvers with escalation. When None, creates a simple
            single-approver self-attestation.
    """
    api_key = _get_api_key()
    if not api_key:
        _log_call("attestation_error", reason="no_api_key")
        logger.error("XCHK_API_KEY not set")
        return None

    body = {
        "user": target_email,
        "prompt": prompt,
        "type": "t/f",
        "ttl": ATTESTATION_TTL_SECONDS // 60,  # minutes
    }

    if levels:
        # Pass the levels directly — server handles team role resolution,
        # sibling creation, progressive notification, etc.
        body["levels"] = levels
        _log_call("attestation_levels", levels=levels)
    else:
        # Fallback: single-approver self-attestation (backward compat)
        body["levels"] = [
            {"role": "approver", "n": 1, "preferred": [target_email], "autoEscalate": False},
        ]

    payload = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        f"{XCHK_BASE}/api/attestations",
        data=payload,
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        ctx = _SSL_CONTEXT if _SSL_CONTEXT else ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            att_id = data.get("attestationId")
            _log_call("attestation_created", attestation_id=att_id, prompt=prompt, target=target_email)
            return att_id
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        _log_call("attestation_error", http_status=e.code, body=body)
        logger.error("Failed to create attestation: %s %s", e.code, body)
        return None
    except Exception as e:
        _log_call("attestation_error", error=str(e))
        logger.error("Failed to create attestation: %s", e)
        return None


def _poll_attestation(att_id: str, timeout_seconds: int = 180) -> Dict[str, Any]:
    """Poll an attestation until resolved or timeout. Returns the result."""
    api_key = _get_api_key()
    if not api_key:
        return {"status": "error", "reason": "no_api_key"}

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        req = urllib.request.Request(
            f"{XCHK_BASE}/api/attestations/{att_id}",
            headers={"X-API-Key": api_key},
            method="GET",
        )
        try:
            ctx = _SSL_CONTEXT if _SSL_CONTEXT else ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                status = data.get("status")
                _log_call("attestation_poll", attestation_id=att_id, status=status)
                if status in ("completed", "declined", "expired"):
                    return {
                        "status": status,
                        "response": data.get("response"),
                        "attestation_id": att_id,
                        "confidence": data.get("confidence_indicator"),
                    }
        except urllib.error.HTTPError as e:
            _log_call("attestation_poll_error", attestation_id=att_id, http_status=e.code)
        except Exception as e:
            _log_call("attestation_poll_error", attestation_id=att_id, error=str(e))

        time.sleep(2)

    return {"status": "timeout", "reason": "timed out waiting for approval"}


def _summarize_args(tool_name: str, args: dict) -> str:
    """Build a compact summary of the tool call for the attestation prompt."""
    if tool_name == "terminal":
        cmd = (args.get("command") or "")[:500]
        return f"`{cmd}`"
    elif tool_name == "read_file":
        return f"Path: {args.get('path', '?')} (lines {args.get('offset', 1)}-{args.get('offset', 1) + args.get('limit', 500) - 1})"
    elif tool_name == "write_file":
        return f"Path: {args.get('path', '?')} (content length: {len(args.get('content', ''))} chars)"
    elif tool_name == "patch":
        path = args.get("path", "?")
        mode = args.get("mode", "replace")
        return f"Path: {path} (mode: {mode})"
    elif tool_name == "search_files":
        return f"Pattern: {args.get('pattern', '?')} in {args.get('path', '.')}"
    elif tool_name == "execute_code":
        code_len = len(args.get("code", ""))
        return f"Python code ({code_len} chars)"
    elif tool_name == "delegate_task":
        goal = (args.get("goal") or args.get("tasks", [{}])[0].get("goal", "?"))[:200]
        return f"Goal: {goal}"
    elif tool_name == "browser_navigate":
        return f"URL: {args.get('url', '?')}"
    elif tool_name == "web_search":
        return f"Query: {args.get('query', '?')}"
    elif tool_name == "memory":
        return f"Action: {args.get('action', '?')}"
    elif tool_name == "clarify":
        return f"Question: {(args.get('question', '?'))[:200]}"
    elif tool_name == "vision_analyze":
        return f"Image: {args.get('image_url', '?')}"
    elif tool_name == "image_generate":
        return f"Prompt: {(args.get('prompt', '?'))[:200]}"
    elif tool_name == "skill_view":
        return f"Skill: {args.get('name', '?')}"
    elif tool_name == "wx_conditions" or tool_name == "wx_forecast":
        return f"Lat: {args.get('lat', '?')}, Lon: {args.get('lon', '?')}"
    else:
        return json.dumps(args, indent=0)[:300]


def _require_attestation(
    tool_name: str,
    args: dict,
    next_call: callable,
    owner: str = "sean@maclawran.ca",
    danger_desc: str = "",
    levels: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Require attestation for a tool call. Blocks until approved.

    Args:
        tool_name: Name of the tool being called.
        args: Tool arguments.
        next_call: Function to execute the actual tool call.
        owner: Fallback target email (used when no levels provided).
        danger_desc: Danger description for the prompt.
        levels: Policy levels for multi-approver routing. When provided,
            these define who gets notified and the escalation chain.
            When None, falls back to single-approver self-attestation.
    """
    label = _TOOL_LABELS.get(tool_name, tool_name)
    summary = _summarize_args(tool_name, args)

    if danger_desc:
        prompt = f"⚠️  {danger_desc}\n\n{label}\n\n{summary}"
    else:
        prompt = f"Approve {label}?\n\n{summary}"

    _log_call("attestation_required", tool_name=tool_name, prompt=prompt)
    _log_call("attestation_levels_check", levels_present=levels is not None, levels_count=len(levels) if levels else 0)

    att_id = _create_attestation(prompt, owner, levels=levels)
    if not att_id:
        error_msg = f"BLOCKED: Failed to create attestation for {tool_name}. Check XCHK_API_KEY."
        _log_call("blocked", reason="attestation_creation_failed", tool_name=tool_name)
        return json.dumps({"error": error_msg, "blocked": True})

    result = _poll_attestation(att_id, timeout_seconds=POLL_TIMEOUT)

    if result.get("status") == "completed" and result.get("response") == "approved":
        _log_call("attestation_approved", attestation_id=att_id, tool_name=tool_name)
        # Execute the command and strip UID sentinel from output
        output = next_call(args)
        if tool_name == "terminal":
            output = _strip_uid_marker(output)
        return output
    elif result.get("status") == "declined":
        error_msg = f"BLOCKED: {label} was DECLINED."
        _log_call("blocked", reason="declined", attestation_id=att_id, tool_name=tool_name)
        return json.dumps({"error": error_msg, "blocked": True})
    else:
        reason = result.get("reason", result.get("status", "unknown"))
        error_msg = f"BLOCKED: {label} — attestation {result.get('status')}: {reason}"
        _log_call("blocked", reason=result.get("status"), attestation_id=att_id, tool_name=tool_name)
        return json.dumps({"error": error_msg, "blocked": True})


def tool_execution_middleware(
    tool_name: str,
    args: dict,
    next_call: callable,
    **context,
):
    """TOOL_EXECUTION_MIDDLEWARE callback.

    Default mode (BLOCK_ALL=false): only dangerous commands/files trigger
    attestation. Uses Hermes' own detect_dangerous_command() with the same
    ~50 patterns the terminal tool uses — same coverage, same robustness.

    BLOCK_ALL=true mode: every tool call requires attestation (legacy).
    """
    _log_call("tool_execution", tool_name=tool_name, args=args)

    # Infrastructure tools — never block these
    if tool_name in ALWAYS_ALLOW_TOOLS:
        return next_call(args)

    # ── BLOCK ALL MODE ──────────────────────────────────────────
    if BLOCK_ALL:
        if tool_name == "clarify":
            return _require_attestation(tool_name, args, next_call)
        return _require_attestation(tool_name, args, next_call)

    # ── DANGEROUS-COMMAND MODE (default) ────────────────────────
    # Only intercept terminal commands and file writes that match
    # Hermes' dangerous patterns. Everything else passes through.

    if tool_name == "terminal":
        command = (args.get("command") or "").strip()
        if not command:
            return next_call(args)

        # ── Wrap command with post-exec UID check ───────────────
        # Inject a sentinel that captures effective UID after the
        # command completes. This detects privilege escalation even
        # for zero-day exploits not in our pattern list.
        wrapped_command = _wrap_with_uid_check(command)
        uid_wrapped = wrapped_command != command
        if uid_wrapped:
            args = dict(args)
            args["command"] = wrapped_command

        # Check if it's an SSH to a guarded host — check the remote command
        for resource in RESOURCES:
            host = resource["host"]
            if _is_ssh_to_host(command, host):
                remote_cmd = _extract_remote_command(command)
                if remote_cmd:
                    is_dangerous, desc = _is_command_dangerous(remote_cmd)
                    if is_dangerous:
                        # Use the resource's levels for proper multi-approver routing
                        resource_levels = resource.get("levels")
                        return _require_attestation(
                            tool_name, args, next_call,
                            owner=resource["owner"],
                            danger_desc=desc,
                            levels=resource_levels,
                        )
                break

        # Also check local commands against dangerous patterns
        is_dangerous, desc = _is_command_dangerous(command)
        if is_dangerous:
            return _require_attestation(
                tool_name, args, next_call,
                danger_desc=desc,
            )

        # Safe command — let it through, but check UID after
        result = next_call(args)

        # ── Post-execution UID check ─────────────────────────────
        uid_danger = _check_uid_change(result, command)
        if uid_danger:
            # Command already ran — this is an alert, not a prevention.
            # Create an attestation immediately to alert the user.
            _log_call("uid_escalation_detected", command=command[:300],
                      uid_change=uid_danger)
            # Check which resource this SSH targeted, if any
            uid_levels = None
            for resource in RESOURCES:
                if _is_ssh_to_host(command, resource["host"]):
                    uid_levels = resource.get("levels")
                    break
            _create_attestation(
                uid_danger,
                owner="sean@maclawran.ca",
                levels=uid_levels,
            )
            # Return the command output prefixed with an alert banner
            alert = (
                f"\n{'='*60}\n"
                f"🚨 PRIVILEGE ESCALATION DETECTED 🚨\n"
                f"{'='*60}\n"
                f"The command above changed the effective UID from "
                f"{_EXPECTED_UID} ({_EXPECTED_USER}) to something else.\n"
                f"An xChk attestation has been created for review.\n"
                f"{'='*60}\n"
            )
            if uid_wrapped:
                result = _strip_uid_marker(result)
            return alert + "\n" + result

        # Strip the sentinel before returning to the agent
        if uid_wrapped:
            result = _strip_uid_marker(result)
        return result

    elif tool_name == "write_file":
        path = args.get("path", "")
        if _is_sensitive_write(path):
            return _require_attestation(
                tool_name, args, next_call,
                danger_desc=f"Write to sensitive path: {path}",
            )
        return next_call(args)

    elif tool_name == "patch":
        path = args.get("path", "")
        if _is_sensitive_write(path):
            return _require_attestation(
                tool_name, args, next_call,
                danger_desc=f"Edit sensitive path: {path}",
            )
        return next_call(args)

    # Everything else passes through
    return next_call(args)


def register(ctx) -> None:
    """Register middleware callbacks."""
    logger.info("attestation-guardrails: registering tool execution middleware (BLOCK_ALL=%s)", BLOCK_ALL)

    api_key = _get_api_key()
    if not api_key:
        logger.warning("XCHK_API_KEY not found in env — attestation requests will fail")

    ctx.register_middleware("tool_execution", tool_execution_middleware)
    _log_call("plugin_register", middleware="tool_execution", status="registered",
              api_key_set=bool(api_key), block_all=BLOCK_ALL)
    logger.info("attestation-guardrails: registered. Block-all=%s. Logging to %s", BLOCK_ALL, CALLBACKS_LOG)
