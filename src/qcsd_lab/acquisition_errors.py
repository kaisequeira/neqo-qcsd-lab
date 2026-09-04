"""Typed transient failures shared by public-page acquisition stages."""

from __future__ import annotations


class RecoverableAcquisitionError(RuntimeError):
    """A transient external failure for which the frozen retry policy applies."""


class TerminalAcquisitionPolicyError(ValueError):
    """A deterministic acquisition-policy rejection with optional safe evidence."""

    def __init__(self, message: str, *, evidence: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class PassiveRenderPolicyError(TerminalAcquisitionPolicyError):
    """The bounded passive-render observation could not reach quiescence."""
