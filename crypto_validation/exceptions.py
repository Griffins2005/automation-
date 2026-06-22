"""Framework-specific exception types."""


class ValidationFrameworkError(Exception):
    """Base class for expected framework errors."""


class ConfigError(ValidationFrameworkError):
    """Raised when a user configuration is invalid."""


class ParseError(ValidationFrameworkError):
    """Raised when a vector file cannot be parsed."""


class DutError(ValidationFrameworkError):
    """Raised when a DUT fails to execute or returns invalid output."""


class UnsupportedTestError(ValidationFrameworkError):
    """Raised when a requested algorithm, mode, or test type is unsupported."""
