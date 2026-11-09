from dataclasses import dataclass
from .argon2_derivation import Argon2DerivationResult
from .hkdf_derivation import HKDFDerivationResult, AVAILABLE_HASH_ALGORITHMS
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class HKDFDerivationRequest:
    id: str
    length: int
    info: bytes

    def __post_init__(self):
        if not isinstance(self.id, str):
            raise TypeError("id must be a string")
        if len(self.id) == 0:
            raise ValueError("id cannot be empty")
        if self.id != self.id.strip():
            raise ValueError("id cannot contains spaces or tabulations")
        if isinstance(self.length, bool) or not isinstance(self.length, int):
            raise TypeError("length must be an integer")
        if self.length < 1:
            raise ValueError("length must be positive")
        if not isinstance(self.info, bytes):
            raise TypeError("info must be bytes")

@dataclass(frozen=True)
class CombinedDerivationResult:
    argon2_result: Argon2DerivationResult
    hkdf_salt: bytes | None
    hash_algorithm: str
    requests: tuple[HKDFDerivationRequest, ...]
    keys: Mapping[str, HKDFDerivationResult]

    def __post_init__(self):
        if not isinstance(self.argon2_result, Argon2DerivationResult):
            raise TypeError("argon2_result must be a Argon2DerivationResult")
        if self.hkdf_salt is not None and not isinstance(self.hkdf_salt, bytes):
            raise TypeError("hkdf_salt must be bytes or None")
        
        if not isinstance(self.hash_algorithm, str):
            raise TypeError("hash_algorithm must be a string")
        if len(self.hash_algorithm) == 0:
            raise ValueError("hash_algorithm cannot be empty")
        if self.hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
            raise ValueError(f"hash_algorithm must be in {AVAILABLE_HASH_ALGORITHMS}")
        
        if not isinstance(self.requests, tuple):
            raise TypeError("requests must be a tuple")
        if len(self.requests) == 0:
            raise ValueError("requests cannot be empty")
        for request in self.requests:
            if not isinstance(request, HKDFDerivationRequest):
                raise TypeError(
                    "all requests must be HKDFDerivationRequest instances"
                )

        request_ids = [request.id for request in self.requests]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("request ids must be unique")

        if not isinstance(self.keys, Mapping):
            raise TypeError("keys must be a mapping")

        expected_ids = set(request_ids)
        provided_ids = set(self.keys.keys())

        if expected_ids != provided_ids:
            raise ValueError("keys must contain exactly the ids defined in requests")

        for request in self.requests:
            result = self.keys[request.id]

            if not isinstance(result, HKDFDerivationResult):
                raise TypeError(f"key '{request.id}' must be an HKDFDerivationResult")

            if result.length != request.length:
                raise ValueError(f"key '{request.id}' has an incorrect length")

            if result.hash_algorithm != self.hash_algorithm:
                raise ValueError(f"key '{request.id}' uses an incorrect hash algorithm")

        immutable_keys = MappingProxyType(dict(self.keys))

        object.__setattr__(self, "keys", immutable_keys)
