import hashlib
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
