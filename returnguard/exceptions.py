"""Exceptions for returnguard."""


class ReturnGuardError(Exception):
    """Base exception for returnguard."""


class ScoringError(ReturnGuardError):
    """Raised when fraud scoring fails."""


class ProfileError(ReturnGuardError):
    """Raised on invalid customer profile."""


class ValidationError(ReturnGuardError):
    """Raised on invalid return request data."""
