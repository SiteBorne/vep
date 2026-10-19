"""Exception hierarchy with stable CLI exit codes."""
from __future__ import annotations


class VepError(Exception):
    exit_code = 1


class CanonicalError(VepError):
    exit_code = 10


class SchemaError(VepError):
    exit_code = 11


class ObjectNotFound(VepError):
    exit_code = 12


class CorruptObject(VepError):
    exit_code = 13


class SnapshotError(VepError):
    exit_code = 14


class StateError(VepError):
    """Illegal or stale candidate state transition."""
    exit_code = 15


class PolicyViolation(VepError):
    exit_code = 3


class BudgetError(VepError):
    exit_code = 5


class AuthorizationError(VepError):
    exit_code = 7


class IsolationUnavailable(VepError):
    exit_code = 8


class VerificationFailed(VepError):
    exit_code = 4


class FalseGreen(VepError):
    """Evaluation output looked successful without establishing that tests ran and passed."""
    exit_code = 9


class ExecutionError(VepError):
    exit_code = 16


class ContextBudgetExceeded(VepError):
    exit_code = 6
