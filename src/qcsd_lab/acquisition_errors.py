"""Typed transient failures shared by public-page acquisition stages."""

from __future__ import annotations


class RecoverableAcquisitionError(RuntimeError):
    """A transient external failure for which the frozen retry policy applies."""


class PreparationError(RuntimeError):
    """A malformed or internally inconsistent preparation result."""


class RecoverablePreparationError(PreparationError, RecoverableAcquisitionError):
    """A transient live HTTP/3 preparation failure that may be retried."""


class FullGraphH3PolicyError(RecoverablePreparationError):
    """A complete discovered graph contains an unavailable HTTP/3 resource.

    Historical callers still treat this as recoverable. Prospective selection
    may defer the observation only after independently reopening its evidence.
    A resolved negative manifest and an exact source-bound peer transport
    rejection use distinct raw evidence schemas; neither prunes the graph.
    """

    def __init__(self, message: str, *, evidence: dict[str, object]) -> None:
        super().__init__(message)
        self.evidence = evidence


class ResponseStabilityPolicyError(RecoverablePreparationError):
    """Successful repeated runs do not preserve every response identity."""

    def __init__(self, message: str, *, evidence: dict[str, object]) -> None:
        super().__init__(message)
        self.evidence = evidence


class TerminalAcquisitionPolicyError(ValueError):
    """A deterministic acquisition-policy rejection with optional safe evidence."""

    def __init__(self, message: str, *, evidence: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


class PassiveRenderPolicyError(TerminalAcquisitionPolicyError):
    """The bounded passive-render observation could not reach quiescence."""


class NonReplayableEgressPolicyError(TerminalAcquisitionPolicyError):
    """Browser content attempted an egress API the prepared workload cannot replay."""
