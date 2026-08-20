class CyberKimiError(Exception):
    """Base exception."""


class ValidationFailure(CyberKimiError):
    pass


class AuthorizationError(CyberKimiError):
    pass


class ScopeTokenError(AuthorizationError):
    pass


class ApprovalError(AuthorizationError):
    pass


class BudgetExceeded(AuthorizationError):
    pass


class ToolExecutionError(CyberKimiError):
    pass


class ProviderBoundaryError(CyberKimiError):
    pass
