import hmac, hashlib, math

AVAILABLE_HASH_ALGORITHMS = ["sha256", "sha384", "sha512"]
HASH_ALGORITHMS_METADATA = {
    "sha256": {
        "hash_length": 32,
        "algorithm": hashlib.sha256
    },
    "sha384":{
        "hash_length": 48,
        "algorithm": hashlib.sha384
    },
    "sha512": {
        "hash_length": 64,
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
        effective_salt = b"\x00" * hash_metadata["hash_length"]
    else:
        effective_salt = salt
    prk = hmac.new(effective_salt, ikm, effective_hash)
    return prk.digest()

def _hkdf_expand(prk: bytes, length: int, info: bytes, hash_algorithm: str) -> bytes:
    if not isinstance(prk, bytes):
        raise TypeError("prk must be bytes")
    if len(prk) == 0:
        raise ValueError("prk cannot be empty")
    if  isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 1:
        raise ValueError("length must be positive")
    if not isinstance(info, bytes):
        raise TypeError("info must be bytes")
    if not isinstance(hash_algorithm, str):
        raise TypeError("hash_algorithm must be a string")
    if hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
        raise ValueError(f"hash_algorithm must be in {AVAILABLE_HASH_ALGORITHMS}")
    hash_metadata = HASH_ALGORITHMS_METADATA[hash_algorithm]
    hash_length = hash_metadata["hash_length"]
    hash_constructor = hash_metadata["algorithm"]
    if len(prk) != hash_length:
        raise ValueError("prk must have the HashLength of the hash_algorithm")
    if length > 255*hash_length:
        raise ValueError("length must be lower or equal than 255*HashLength")
    previous_block = b""
    full_okm = b""
    num_blocks = math.ceil(float(length)/hash_length)
    for i in range(1, num_blocks + 1):
        message = previous_block + info + i.to_bytes(length=1, byteorder="big")
        new_block = hmac.new(prk, message, hash_constructor).digest()
        full_okm += new_block
        previous_block = new_block
    return full_okm[:length]