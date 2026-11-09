from .requests import HKDFDerivationRequest
from .results import CombinedDerivationResult
from kdf_tool.argon2 import Argon2DerivationResult
from kdf_tool.hkdf import HKDFDerivationResult, AVAILABLE_HASH_ALGORITHMS, HASH_ALGORITHMS_METADATA
from kdf_tool.hkdf.expand import _hkdf_expand

class DerivationContext:

    def __init__(self, prk: bytes, argon2_result: Argon2DerivationResult, hash_algorithm: str, hkdf_salt: bytes | None = None):
        if not isinstance(prk, bytes):
            raise TypeError("prk must be bytes")
        if len(prk) == 0:
            raise ValueError("prk cannot be empty")

        if not isinstance(hash_algorithm, str):
            raise TypeError("hash_algorithm must be a string")
        if hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
            raise ValueError(f"hash_algorithm must be in {AVAILABLE_HASH_ALGORITHMS}")

        if hkdf_salt is not None and not isinstance(hkdf_salt, bytes):
            raise TypeError("hkdf_salt must be bytes or None")

        hash_length = HASH_ALGORITHMS_METADATA[hash_algorithm]["hash_length"]

        if len(prk) != hash_length:
            raise ValueError("prk must have the HashLength of the hash_algorithm")

        self._prk = prk
        self._argon2_result = argon2_result
        self._hash_algorithm = hash_algorithm
        self._hkdf_salt = hkdf_salt

        self._requests: list[HKDFDerivationRequest] = []
        self._keys: dict[str, HKDFDerivationResult] = {}

        self._closed = False
    
    def derive_key(self, request: HKDFDerivationRequest) -> HKDFDerivationResult:

        if self._closed:
            raise ValueError("context is closed")

        if not isinstance(request, HKDFDerivationRequest):
            raise TypeError("request must be an HKDFDerivationRequest")

        if request.id in self._keys:
            raise ValueError(f"a key with id '{request.id}' already exists")

        if self._prk is None:
            raise ValueError("context is closed")

        key = _hkdf_expand(
            prk=self._prk,
            length=request.length,
            info=request.info,
            hash_algorithm=self._hash_algorithm
        )

        result = HKDFDerivationResult(
            key=key,
            length=len(key),
            hash_algorithm=self._hash_algorithm
        )

        self._requests.append(request)
        self._keys[request.id] = result

        return result
    
    def get_key(self, id: str) -> HKDFDerivationResult:

        if self._closed:
            raise ValueError("context is closed")

        if not isinstance(id, str):
            raise TypeError("id must be a string")

        if len(id) == 0:
            raise ValueError("id cannot be empty")

        if id not in self._keys:
            raise KeyError(f"key '{id}' does not exist")

        return self._keys[id]

    def get_result(self) -> CombinedDerivationResult:

        if self._closed:
            raise ValueError("context is closed")

        if len(self._requests) == 0:
            raise ValueError("no keys have been derived")

        return CombinedDerivationResult(
            argon2_result=self._argon2_result,
            hkdf_salt=self._hkdf_salt,
            hash_algorithm=self._hash_algorithm,
            requests=tuple(self._requests),
            keys=self._keys
        )

    def close(self) -> None:

        if self._closed:
            return

        self._prk = None
        self._closed = True

    def __enter__(self):
        if self._closed:
            raise ValueError("context is closed")

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
