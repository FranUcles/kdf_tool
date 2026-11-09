import secrets
from dataclasses import dataclass, field
from .argon2_config import Argon2Config
from .exceptions import Argon2DerivationException

from argon2.low_level import hash_secret_raw, Type
from argon2.exceptions import HashingError

_SALT_LENGTH = 16

def _generate_salt() -> bytes:
    return secrets.token_bytes(_SALT_LENGTH)

@dataclass(frozen=True)
class Argon2DerivationResult():
    key: bytes
    salt: bytes
    algorithm: str = field(default="argon2id", init=False)
    version: int = field(init=False)
    parameters: Argon2Config

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes):
            raise TypeError("key must be bytes")
        if not isinstance(self.salt, bytes):
            raise TypeError("salt must be bytes")
        if not isinstance(self.parameters, Argon2Config):
            raise TypeError("parameters must be Argon2Config")
        if len(self.salt) < _SALT_LENGTH:
            raise ValueError(f"salt must contain at least {_SALT_LENGTH} bytes")
        if len(self.key) != self.parameters.hash_len:
            raise ValueError("key length must match parameters.hash_len")
        object.__setattr__(self, "version", self.parameters.version)

def derive_argon2id(secret: bytes, config: Argon2Config) -> Argon2DerivationResult:
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    if len(secret) == 0:
        raise ValueError("secret cannot be empty")
    if not isinstance(config, Argon2Config):
        raise TypeError("config must be Argon2Config")

    salt = _generate_salt()
    try:
        key = hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=config.time_cost,
            memory_cost=config.memory_cost,
            parallelism=config.parallelism,
            hash_len=config.hash_len,
            type=Type.ID,
            version=config.version
        )
    except HashingError as exc:
        raise Argon2DerivationException("Error during Argon2id derivation") from exc

    return Argon2DerivationResult(key=key, salt=salt, parameters=config)