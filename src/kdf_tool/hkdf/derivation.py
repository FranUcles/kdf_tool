from dataclasses import dataclass
from .algorithms import AVAILABLE_HASH_ALGORITHMS
from .extract import _hkdf_extract
from .expand import _hkdf_expand

@dataclass(frozen=True)
class HKDFDerivationResult():
    key: bytes
    length: int
    hash_algorithm: str

    def __post_init__(self):
        if not isinstance(self.key, bytes):
            raise TypeError("key must be bytes")
        if len(self.key) == 0:
            raise ValueError("key cannot be empty")
        if isinstance(self.length, bool) or not isinstance(self.length, int):
            raise TypeError("length must be an integer")
        if self.length < 1:
            raise ValueError("length must be positive")
        if len(self.key) != self.length:
            raise ValueError("key must have the provided length")
        if not isinstance(self.hash_algorithm, str):
            raise TypeError("hash_algorithm must be a string")
        if len(self.hash_algorithm) == 0:
            raise ValueError("hash_algorithm cannot be empty")
        if self.hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
            raise ValueError(f"hash_algorithm must be in {AVAILABLE_HASH_ALGORITHMS}")

def derive_hkdf(ikm: bytes, length: int, salt: bytes | None = None, 
                info: bytes = b"", hash_algorithm: str = "sha256") -> HKDFDerivationResult:
    if not isinstance(ikm, bytes):
        raise TypeError("ikm must be bytes")
    if len(ikm) == 0:
        raise ValueError("ikm cannot be empty")
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 1:
        raise ValueError("length must be positive")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("salt must be bytes or None")
    if not isinstance(info, bytes):
        raise TypeError("info must be bytes")
    if not isinstance(hash_algorithm, str):
        raise TypeError("hash_algorithm must be a string")
    if len(hash_algorithm) == 0:
        raise ValueError("hash_algorithm cannot be empty")
    if hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
        raise ValueError(f"hash_algorithm must be in {AVAILABLE_HASH_ALGORITHMS}")
    prk = _hkdf_extract(ikm, hash_algorithm, salt)
    okm = _hkdf_expand(prk, length, info, hash_algorithm)
    return HKDFDerivationResult(key=okm, length=len(okm), hash_algorithm=hash_algorithm)