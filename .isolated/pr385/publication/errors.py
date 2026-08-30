"""Publication governance errors.

Exceptions are only used for local developer misuse. Runtime decision paths
return fail-closed result objects instead of raising.
"""


class PublicationError(Exception):
    """Base exception for publication runtime foundation errors."""


class PublicationPolicyError(PublicationError):
    """Raised when a local policy file cannot be loaded by caller request."""


class PublicationRegistryError(PublicationError):
    """Raised when a local registry file cannot be loaded by caller request."""
