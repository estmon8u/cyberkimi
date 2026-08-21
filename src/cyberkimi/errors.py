"""Typed CyberKimi exceptions."""


class CyberKimiError(Exception):
    """Base error for user-visible CyberKimi failures."""


class ValidationFailure(CyberKimiError):
    """Input failed a local validation boundary."""


class AuthorizationError(CyberKimiError):
    """Authorization could not be established or verified."""


class PolicyDenied(CyberKimiError):
    """A proposed action was denied by immutable policy."""


class ApprovalRequired(CyberKimiError):
    """An exact action approval is required."""


class GrantError(CyberKimiError):
    """Execution grant validation or consumption failed."""


class AuditWriteError(CyberKimiError):
    """Audit persistence failed; execution must fail closed."""


class ToolUnavailable(CyberKimiError):
    """A pinned external adapter is not installed or usable."""


class ProviderBoundary(CyberKimiError):
    """The model provider declined the request on policy grounds."""


class BudgetExceeded(CyberKimiError):
    """A hard task or execution budget would be exceeded."""


class DataPolicyError(CyberKimiError):
    """External data exposure is blocked by the immutable engagement policy."""
