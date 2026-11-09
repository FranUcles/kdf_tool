import secrets

_SALT_LENGTH = 16

def _generate_salt() -> bytes:
    return secrets.token_bytes(_SALT_LENGTH)