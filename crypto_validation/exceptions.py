"""Framework-specific exception types.

These exceptions mark expected failure categories. The CLI and validation engine
convert them into stable statuses and exit codes instead of exposing raw Python
tracebacks to users.
"""


class ValidationFrameworkError(Exception):
    """Base class for expected framework errors.

    Catch this when a caller wants to handle all framework-defined errors
    without catching unrelated Python exceptions.
    """


class ConfigError(ValidationFrameworkError):
    """Raised when a user configuration is invalid."""


class ParseError(ValidationFrameworkError):
    """Raised when a vector file cannot be parsed into valid test cases."""


class DutError(ValidationFrameworkError):
    """Raised when a DUT fails to execute or returns invalid output."""


class UnsupportedTestError(ValidationFrameworkError):
    """Raised when a requested algorithm, mode, DUT, or test type is unsupported."""
