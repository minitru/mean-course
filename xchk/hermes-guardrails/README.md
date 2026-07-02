# xChk Attestation Guardrails — Hermes Agent Plugin

This directory contains the **Hermes Agent plugin** that intercepts
dangerous AI agent tool calls and requires xChk attestation approval
before execution.

## How It Works

The plugin registers a `tool_execution_middleware` callback in Hermes.
Before every tool call, it checks:

1. **Terminal commands** — passed through Hermes' own
   `detect_dangerous_command()` from `tools.approval`, which has ~50
   compiled regex patterns covering rm -rf, chmod 777, mkfs, dd, SQL
   DROP/DELETE, systemctl stop, kill -9, curl|bash, git force push,
   find -delete, sudo escalation, sed/perl in-place edits of sensitive
   files, and more. Also checks the unconditional `HARDLINE_PATTERNS`
   (rm -rf /, mkfs, dd to raw device, fork bombs, shutdown/reboot).

2. **SSH to guarded hosts** — extracts the remote command and checks it
   against the same patterns.

3. **write_file / patch** — checks if the target path is a sensitive file
   (~/.ssh/*, ~/.bashrc, /etc/*, ~/.hermes/config.yaml, project .env, etc.)

If a match is found, the plugin creates an xChk attestation and **blocks
the agent** until the attestation is approved or the TTL (5 min) expires.

Safe commands (ls, cat, read_file, web_search, weather, etc.) pass
through instantly with no attestation.

## Files

- `__init__.py` — The plugin itself (middleware, attestation creation,
  command detection)
- `plugin.yaml` — Hermes plugin manifest

## Setup

1. Copy the `attestation-guardrails` directory to `~/.hermes/plugins/`
2. Set `XCHK_API_KEY` in your Hermes `.env` file
3. Restart Hermes

The plugin logs to `/tmp/CALLBACKS` for debugging.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `XCHK_BLOCK_ALL` | `false` | Block every tool call (true) or only dangerous ones (false) |
| `XCHK_API_KEY` | (required) | xChk API key for attestation API |

## Requirements

- Hermes Agent (for `tools.approval.detect_dangerous_command`)
- Python 3.10+
- `certifi` (recommended for SSL)
