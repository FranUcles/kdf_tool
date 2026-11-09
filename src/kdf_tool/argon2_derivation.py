import secrets
from dataclasses import dataclass, field
from .argon2_config import Argon2Config

_SALT_LENGTH = 16

def _generate_salt() -> bytes:
    return secrets.token_bytes(_SALT_LENGTH)

@dataclass(frozen=True)
class DerivationResult():
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