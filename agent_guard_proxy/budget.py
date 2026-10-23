"""
Token and Financial Cost Budget Guard for Autonomous AI Agent MCP sessions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional


class BudgetViolation(Exception):
    def __init__(self, message: str, current_spend: float, limit: float):
        super().__init__(message)
        self.current_spend = current_spend
        self.limit = limit


@dataclass
class BudgetConfig:
    max_session_cost_usd: float = 10.0
    max_session_tokens: int = 250_000
    cost_per_1k_input_tokens: float = 0.003
    cost_per_1k_output_tokens: float = 0.015


class BudgetGuard:
    """
    Enforces token usage ceilings and monetary cost thresholds across MCP calls.
    """

    def __init__(self, config: Optional[BudgetConfig] = None):
        self.config = config or BudgetConfig()
        self.total_tokens_consumed: int = 0
        self.total_cost_usd: float = 0.0
        self.total_calls: int = 0

    @staticmethod
    def estimate_tokens(data: Any) -> int:
        """
        Heuristic token estimator (average 4 chars per token for JSON text).
        """
        if isinstance(data, str):
            text = data
        else:
            try:
                text = json.dumps(data)
            except Exception:
                text = str(data)
        # Standard NLP rule of thumb: ~4 characters per token
        return max(1, len(text) // 4)

    def track_call(self, request_payload: Any, response_payload: Optional[Any] = None) -> float:
        """
        Tracks token consumption for an MCP call and charges cost.
        Raises BudgetViolation if session ceilings are breached.
        """
        in_tokens = self.estimate_tokens(request_payload)
        out_tokens = self.estimate_tokens(response_payload) if response_payload else 0
        call_tokens = in_tokens + out_tokens

        call_cost = (
            (in_tokens / 1000.0) * self.config.cost_per_1k_input_tokens
            + (out_tokens / 1000.0) * self.config.cost_per_1k_output_tokens
        )

        projected_cost = self.total_cost_usd + call_cost
        projected_tokens = self.total_tokens_consumed + call_tokens

        if projected_cost > self.config.max_session_cost_usd:
            raise BudgetViolation(
                f"Financial budget breached: Projected ${projected_cost:.4f} > Limit ${self.config.max_session_cost_usd:.2f}",
                current_spend=projected_cost,
                limit=self.config.max_session_cost_usd,
            )

        if projected_tokens > self.config.max_session_tokens:
            raise BudgetViolation(
                f"Token budget breached: Projected {projected_tokens} tokens > Limit {self.config.max_session_tokens}",
                current_spend=float(projected_tokens),
                limit=float(self.config.max_session_tokens),
            )

        self.total_tokens_consumed = projected_tokens
        self.total_cost_usd = projected_cost
        self.total_calls += 1

        return call_cost

    def track_response(self, response_payload: Any) -> float:
        """
        Tracks output tokens returned in MCP response payload and charges against budget.
        Raises BudgetViolation if session ceilings are breached.
        """
        out_tokens = self.estimate_tokens(response_payload)
        cost = (out_tokens / 1000.0) * self.config.cost_per_1k_output_tokens

        projected_cost = self.total_cost_usd + cost
        projected_tokens = self.total_tokens_consumed + out_tokens

        if projected_cost > self.config.max_session_cost_usd:
            raise BudgetViolation(
                f"Financial budget breached on output response: Projected ${projected_cost:.4f} > Limit ${self.config.max_session_cost_usd:.2f}",
                current_spend=projected_cost,
                limit=self.config.max_session_cost_usd,
            )

        if projected_tokens > self.config.max_session_tokens:
            raise BudgetViolation(
                f"Token budget breached on output response: Projected {projected_tokens} tokens > Limit {self.config.max_session_tokens}",
                current_spend=float(projected_tokens),
                limit=float(self.config.max_session_tokens),
            )

        self.total_tokens_consumed = projected_tokens
        self.total_cost_usd = projected_cost
        return cost

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_calls": self.total_calls,
            "total_tokens_consumed": self.total_tokens_consumed,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "max_tokens_allowed": self.config.max_session_tokens,
            "max_budget_usd": self.config.max_session_cost_usd,
            "remaining_budget_usd": max(0.0, self.config.max_session_cost_usd - self.total_cost_usd),
        }
