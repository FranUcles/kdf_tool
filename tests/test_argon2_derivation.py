from kdf_tool.argon2_derivation import _generate_salt
from kdf_tool import DerivationResult, Argon2Config, Argon2ConfigBuilder
import pytest
from dataclasses import FrozenInstanceError

def test_generate_salt_returns_bytes():
    salt = _generate_salt()
    assert isinstance(salt, bytes)


def test_generate_salt_has_correct_length():
    salt = _generate_salt()
    assert len(salt) == 16


def test_generate_salt_generates_different_values():
    salt_1 = _generate_salt()
    salt_2 = _generate_salt()
    assert salt_1 != salt_2

def _generate_valid_argon2config() -> Argon2Config:
    return Argon2ConfigBuilder().set_profile("BASIC").build()

def test_valid_derivation():
    argon2_config = _generate_valid_argon2config()
    key = b"0"*argon2_config.hash_len
    salt = _generate_salt()
    derivation = DerivationResult(key, salt, argon2_config)

    assert derivation.key == key
    assert derivation.salt == salt
    assert derivation.algorithm == "argon2id"
    assert derivation.version == argon2_config.version
    assert derivation.parameters == argon2_config

def test_invalid_key():
    argon2_config = _generate_valid_argon2config()
    with pytest.raises(TypeError):
        DerivationResult("0"*argon2_config.hash_len, _generate_salt(), argon2_config) # type: ignore

def test_invalid_salt():
    argon2_config = _generate_valid_argon2config()
    with pytest.raises(TypeError):
        DerivationResult(b"0"*argon2_config.hash_len, "str salt", argon2_config) # type: ignore

def test_invalid_argon2config():
    with pytest.raises(TypeError):
        DerivationResult(b"key", _generate_salt(), None) # type: ignore

def test_invalid_salt_length():
    argon2_config = _generate_valid_argon2config()
    with pytest.raises(ValueError):
        DerivationResult(b"0"*argon2_config.hash_len, b"0", argon2_config)

def test_invalid_key_length():
    argon2_config = _generate_valid_argon2config()
    with pytest.raises(ValueError):
        DerivationResult(b"123456", _generate_salt(), argon2_config)

@pytest.mark.parametrize(
    "attribute, value",
    [
        ("key", b"new_key"),
        ("salt", b"1234567890123456"),
        ("algorithm", "scrypt"),
        ("version", 1),
        ("parameters", None),
    ],
)
def test_derivation_is_immutable(attribute, value):
    argon2_config = _generate_valid_argon2config()

    derivation = DerivationResult(
        b"0" * argon2_config.hash_len,
        _generate_salt(),
        argon2_config,
    )

    with pytest.raises(FrozenInstanceError):
        setattr(derivation, attribute, value)

def test_version_match():
    argon2_config = _generate_valid_argon2config()
    derivation = DerivationResult(b"0"*argon2_config.hash_len, _generate_salt(), argon2_config)
    assert derivation.version == derivation.parameters.version

def test_version_cannot_be_provided():
    argon2_config = _generate_valid_argon2config()
    with pytest.raises(TypeError):
        derivation = DerivationResult(
                    key= b"0"*argon2_config.hash_len,
                    salt= _generate_salt(),
                    parameters= argon2_config,
                    version=1) # type: ignore

def test_algorithm_cannot_be_provided():
    argon2_config = _generate_valid_argon2config()
    with pytest.raises(TypeError):
        DerivationResult(
            key=b"0" * argon2_config.hash_len,
            salt=_generate_salt(),
            parameters=argon2_config,
            algorithm="scrypt",  # type: ignore
        )