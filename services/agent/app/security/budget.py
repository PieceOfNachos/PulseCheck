"""Per-incident limits on tool calls and LLM tokens."""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings


class BudgetExceeded(Exception):
    """An incident ran past its tool-call or token budget."""


@dataclass
class Budget:
    max_tool_calls: int
    max_tokens: int
    tool_calls: int = 0
    tokens_used: int = 0

    @classmethod
    def from_settings(cls, tool_calls: int = 0, tokens_used: int = 0) -> "Budget":
        """Budget using the configured limits, optionally resuming from saved counters."""
        return cls(settings.max_tool_calls, settings.token_budget, tool_calls, tokens_used)

    def can_call_tool(self) -> bool:
        return self.tool_calls < self.max_tool_calls

    def charge_tool(self) -> None:
        """Count one tool call; raises if the limit was already reached."""
        if not self.can_call_tool():
            raise BudgetExceeded(f"tool call limit reached ({self.max_tool_calls})")
        self.tool_calls += 1

    def charge_tokens(self, n: int) -> None:
        """Add ``n`` tokens; raises once the total goes over the limit.

        The tokens are recorded even when raising, since they were already spent.
        """
        if n < 0:
            raise ValueError("token count cannot be negative")
        self.tokens_used += n
        if self.tokens_used > self.max_tokens:
            raise BudgetExceeded(f"token budget exceeded ({self.tokens_used}/{self.max_tokens})")

    @property
    def tokens_remaining(self) -> int:
        return max(self.max_tokens - self.tokens_used, 0)
