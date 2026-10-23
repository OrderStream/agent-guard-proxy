"""
MCP JSON-RPC Security Guard and Reverse Proxy Core Middleware.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .budget import BudgetConfig, BudgetGuard, BudgetViolation
from .dlp import DLPFilter, DLPViolation
from .rate_limiter import RateLimitExceeded, SlidingWindowRateLimiter


@dataclass
class GuardResult:
    allowed: bool
    sanitized_message: Dict[str, Any]
    error_response: Optional[Dict[str, Any]] = None
    reasons: List[str] = field(default_factory=list)
    dlp_violations: List[DLPViolation] = field(default_factory=list)
    call_cost_usd: float = 0.0


class MCPGuardProxy:
    """
    Enterprise Reverse Proxy & Firewall Middleware for MCP JSON-RPC 2.0 tool calls.
    """

    def __init__(
        self,
        rate_limit_rpm: int = 60,
        budget_config: Optional[BudgetConfig] = None,
        redact_dlp: bool = True,
        block_on_secret_leak: bool = False,
    ):
        self.rate_limiter = SlidingWindowRateLimiter(max_requests=rate_limit_rpm, window_seconds=60.0)
        self.budget_guard = BudgetGuard(budget_config)
        self.dlp_filter = DLPFilter(redact_mode=redact_dlp)
        self.block_on_secret_leak = block_on_secret_leak

    def intercept_request(self, message: Dict[str, Any] | str, client_id: str = "default_client") -> GuardResult:
        """
        Intercepts and inspects client JSON-RPC requests destined for an MCP server.
        """
        if isinstance(message, str):
            try:
                data = json.loads(message)
            except Exception as e:
                return GuardResult(
                    allowed=False,
                    sanitized_message={},
                    error_response=self._json_rpc_error(None, -32700, f"Parse error: {e}"),
                    reasons=[f"Invalid JSON: {e}"],
                )
        else:
            data = message

        req_id = data.get("id")
        method = data.get("method")

        # 1. Rate Limiting Check
        try:
            self.rate_limiter.record_request(client_id)
        except RateLimitExceeded as e:
            return GuardResult(
                allowed=False,
                sanitized_message=data,
                error_response=self._json_rpc_error(req_id, -32029, str(e)),
                reasons=[str(e)],
            )

        # 2. Budget and Token Ceiling Check
        try:
            call_cost = self.budget_guard.track_call(data)
        except BudgetViolation as e:
            return GuardResult(
                allowed=False,
                sanitized_message=data,
                error_response=self._json_rpc_error(req_id, -32030, str(e)),
                reasons=[str(e)],
            )

        # 3. DLP Secret Scan and Redaction on Tool Arguments
        sanitized_data, dlp_violations = self.dlp_filter.scan_and_sanitize_dict(data)

        if dlp_violations and self.block_on_secret_leak:
            types = ", ".join({v.secret_type.value for v in dlp_violations})
            reason = f"DLP Policy Violation: Request contains sensitive secrets ({types})"
            return GuardResult(
                allowed=False,
                sanitized_message=data,
                error_response=self._json_rpc_error(req_id, -32031, reason),
                reasons=[reason],
                dlp_violations=dlp_violations,
                call_cost_usd=call_cost,
            )

        return GuardResult(
            allowed=True,
            sanitized_message=sanitized_data,
            dlp_violations=dlp_violations,
            call_cost_usd=call_cost,
        )

    def intercept_response(self, response: Dict[str, Any] | str) -> Tuple[Dict[str, Any], List[DLPViolation]]:
        """
        Sanitizes server JSON-RPC responses before sending to client, ensuring no secrets leak in output,
        and accounts for output token consumption against session budget limits.
        """
        if isinstance(response, str):
            try:
                data = json.loads(response)
            except Exception:
                return {}, []
        else:
            data = response

        # Track output tokens and enforce budget
        try:
            self.budget_guard.track_response(data)
        except BudgetViolation as e:
            req_id = data.get("id") if isinstance(data, dict) else None
            return self._json_rpc_error(req_id, -32030, str(e)), []

        sanitized_data, violations = self.dlp_filter.scan_and_sanitize_dict(data)
        return sanitized_data, violations

    @staticmethod
    def _json_rpc_error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message,
                "data": {"guard": "agent-guard-proxy"},
            },
        }
