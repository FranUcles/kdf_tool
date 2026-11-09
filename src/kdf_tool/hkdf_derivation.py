import hmac, hashlib

AVAILABLE_HASH_ALGORITHMS = ["sha256", "sha384", "sha512"]
HASH_ALGORITHMS_METADATA = {
    "sha256": {
        "salt_length": 32,
        "algorithm": hashlib.sha256
    },
    "sha384":{
        "salt_length": 48,
        "algorithm": hashlib.sha384
    },
    "sha512": {
        "salt_length": 64,
        "algorithm": hashlib.sha512
    }
}

def _hkdf_extract(ikm: bytes, hash_algorithm: str, salt: bytes | None = None) -> bytes:
    if not isinstance(ikm, bytes):
        raise TypeError("ikm must be bytes")
    if len(ikm) == 0:
        raise ValueError("ikm cannot be empty")
    if not isinstance(hash_algorithm, str):
        raise TypeError("hash_algorithm must be string")
    if hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
        raise ValueError(f"hash_algorithm must in {AVAILABLE_HASH_ALGORITHMS}")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("salt must be bytes or None")
    hash_metadata = HASH_ALGORITHMS_METADATA[hash_algorithm]
    effective_hash = hash_metadata["algorithm"]
    if salt is None or len(salt) == 0:
        effective_salt = b"\x00" * hash_metadata["salt_length"]
    else:
        effective_salt = salt
    prk = hmac.new(effective_salt, ikm, effective_hash)
    return prk.digest()