"""Normalized acquisition errors across all vendor connectors (V3 §13.1, Table 23)."""
from __future__ import annotations


class AcquisitionError(Exception):
    """Base class. ``code`` maps to the normalized ErrorCode; ``retryable`` drives retry policy.

    Messages must be SAFE — never include secrets (V3 §14.2).
    """

    code = "ACQUISITION_ERROR"
    retryable = False

    def __init__(self, message: str = "", *, retryable: bool | None = None):
        super().__init__(message)
        if retryable is not None:
            self.retryable = retryable


class AuthenticationError(AcquisitionError):
    code = "AUTH_FAILED"
    retryable = False  # do not hammer credentials (lockout risk, V3 §13.2)


class AuthorizationError(AcquisitionError):
    code = "AUTHZ_FAILED"
    retryable = False


class ConnectionFailedError(AcquisitionError):
    code = "CONNECTION_FAILED"
    retryable = True


class TimeoutError(AcquisitionError):  # noqa: A001 - intentional domain name
    code = "TIMEOUT"
    retryable = True


class TLSError(AcquisitionError):
    code = "TLS_FAILED"
    retryable = False


class RateLimitedError(AcquisitionError):
    code = "RATE_LIMITED"
    retryable = True


class UnsupportedEndpointError(AcquisitionError):
    code = "UNSUPPORTED_ENDPOINT"
    retryable = False


class MalformedResponseError(AcquisitionError):
    code = "MALFORMED_RESPONSE"
    retryable = False


class PartialDataError(AcquisitionError):
    code = "PARTIAL_DATA"
    retryable = False


class UnsupportedVendorError(AcquisitionError):
    code = "UNSUPPORTED_VENDOR"
    retryable = False
