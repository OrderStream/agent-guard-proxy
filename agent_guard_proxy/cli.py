"""
CLI interface for agent-guard-proxy.
"""

from __future__ import annotations

import argparse
import json
import sys
from .budget import BudgetConfig
from .proxy import MCPGuardProxy


def main():
    parser = argparse.ArgumentParser(
        prog="agent-guard-proxy",
        description="Enterprise reverse proxy & firewall middleware for Model Context Protocol (MCP) JSON-RPC tool calls",
    )
    subparsers = parser.add_subparsers(dest="command")

    # Filter single message
    filter_parser = subparsers.add_parser("check", help="Check a JSON-RPC message against firewall and DLP")
    filter_parser.add_argument("--json", type=str, required=True, help="JSON-RPC payload to inspect")
    filter_parser.add_argument("--block-secrets", action="store_true", help="Block immediately if secrets detected")

    # Redact text
    redact_parser = subparsers.add_parser("redact", help="Scan and redact secrets from input text")
    redact_parser.add_argument("--text", type=str, required=True, help="Text to sanitize")

    args = parser.parse_args()

    if args.command == "check":
        proxy = MCPGuardProxy(
            rate_limit_rpm=60,
            budget_config=BudgetConfig(max_session_cost_usd=5.0),
            redact_dlp=True,
            block_on_secret_leak=args.block_secrets,
        )
        res = proxy.intercept_request(args.json)
        print(json.dumps({
            "allowed": res.allowed,
            "reasons": res.reasons,
            "violations_detected": len(res.dlp_violations),
            "sanitized_payload": res.sanitized_message,
            "cost_usd": res.call_cost_usd,
        }, indent=2))

    elif args.command == "redact":
        from .dlp import DLPFilter
        f = DLPFilter()
        clean, viols = f.redact_text(args.text)
        print(f"Sanitized: {clean}")
        print(f"Redacted secrets: {len(viols)}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
