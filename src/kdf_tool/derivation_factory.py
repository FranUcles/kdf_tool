
from .argon2_config import Argon2Config
from .argon2_derivation import derive_argon2id
from .derivation_context import DerivationContext
from .hkdf_derivation import (
    AVAILABLE_HASH_ALGORITHMS,
    _hkdf_extract,
)


class DerivationFactory:

    @staticmethod
    def create(
        secret: bytes,
        argon2_config: Argon2Config,
        hkdf_salt: bytes | None = None,
        hash_algorithm: str = "sha256"
    ) -> DerivationContext:

        # Validate HKDF parameters before executing Argon2id.
        if not isinstance(hash_algorithm, str):
            raise TypeError("hash_algorithm must be a string")

        if hash_algorithm not in AVAILABLE_HASH_ALGORITHMS:
            raise ValueError(
                f"hash_algorithm must be in {AVAILABLE_HASH_ALGORITHMS}"
            )

        if hkdf_salt is not None and not isinstance(hkdf_salt, bytes):
            raise TypeError("hkdf_salt must be bytes or None")

        # Execute Argon2id.
        argon2_result = derive_argon2id(
            secret=secret,
            config=argon2_config
        )

        # Execute HKDF Extract.
        prk = _hkdf_extract(
            ikm=argon2_result.key,
            hash_algorithm=hash_algorithm,
            salt=hkdf_salt
        )

        # Create the derivation context.
        return DerivationContext(
            prk=prk,
            argon2_result=argon2_result,
            hash_algorithm=hash_algorithm,
            hkdf_salt=hkdf_salt
        )
