"""Unwired operational-provider contract. No backend or activation mechanism."""
from dataclasses import dataclass
from typing import Protocol

from security.hydra_operational_contracts import EvidenceScope


@dataclass(frozen=True)
class ObservationRequest:
    scope: EvidenceScope
    challenge: str


@dataclass(frozen=True)
class ReservationRequest:
    observation: ObservationRequest
    authorization_hash: str
    request_hash: str


@dataclass(frozen=True)
class PreservationRequest:
    observation: ObservationRequest
    through_sequence: int
    through_head: str


class OperationalProviderUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("HYDRA_OPERATIONAL_PROVIDER_UNAVAILABLE")


class OperationalProvider(Protocol):
    def observe_current(self, request: ObservationRequest) -> bytes: ...
    def reserve(self, request: ReservationRequest) -> bytes: ...
    def read_preservation_evidence(self, request: PreservationRequest) -> bytes: ...


class UnavailableOperationalProvider:
    """Always stop before inspecting input, I/O or mutation; never fall back."""
    def observe_current(self, request: ObservationRequest) -> bytes:
        raise OperationalProviderUnavailable()

    def reserve(self, request: ReservationRequest) -> bytes:
        raise OperationalProviderUnavailable()

    def read_preservation_evidence(self, request: PreservationRequest) -> bytes:
        raise OperationalProviderUnavailable()
