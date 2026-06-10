from __future__ import annotations


class VisionProviderError(RuntimeError):
    reason = "PROVIDER_ERROR"


class ProviderMissingError(VisionProviderError):
    reason = "PROVIDER_MISSING"


class ProviderUnknownError(VisionProviderError):
    reason = "PROVIDER_UNKNOWN"


class ProviderTimeoutError(VisionProviderError):
    reason = "PROVIDER_TIMEOUT"


class ProviderMalformedResponseError(VisionProviderError):
    reason = "PROVIDER_RESPONSE_MALFORMED"


class ProviderObservationInvalidError(VisionProviderError):
    reason = "OBSERVATION_REQUIRED_FIELDS_MISSING"
