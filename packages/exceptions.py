"""Domain-specific errors used by the package readers."""


class PackageError(Exception):
    """Base class for failures caused by package data or unsupported operations."""


class PackageFormatError(PackageError, ValueError):
    """The input is not a supported package or contains malformed structures."""


class PackageBoundsError(PackageFormatError):
    """A declared range points outside the source file or containing region."""


class EncryptedEntryError(PackageError):
    """Plaintext was requested from an entry marked as encrypted."""


class UnsupportedFeatureError(PackageError, NotImplementedError):
    """The format is recognized, but the requested operation is not implemented safely."""
