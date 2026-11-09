from kdf_tool.argon2_derivation import _generate_salt, derive_argon2id
from kdf_tool import DerivationResult, Argon2DerivationException, \
                    Argon2Config, Argon2ConfigBuilder
from argon2.exceptions import HashingError
from unittest.mock import patch
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

def _generate_valid_argon2config_low() -> Argon2Config:
    return Argon2ConfigBuilder().set_time_cost(1).set_memory_cost(32)\
                                .set_parallelism(4).set_hash_len(32).build()

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

def test_argon2derivation_exception():
    message = "Test message"
    with pytest.raises(Argon2DerivationException, match=message):
        raise Argon2DerivationException(message)

def test_argon2derivation_invalid_secret():
    with pytest.raises(TypeError):
        derive_argon2id("str secret", _generate_valid_argon2config()) # type: ignore

def test_argon2derivation_invalid_secret_length():
    with pytest.raises(ValueError):
        derive_argon2id(b"", _generate_valid_argon2config())

def test_argon2derivation_invalid_config():
    with pytest.raises(TypeError):
        derive_argon2id(b"secret", None) # type: ignore

def test_argon2derivation_valid_return():
    derivation = derive_argon2id(b"secret", _generate_valid_argon2config_low())
    assert isinstance(derivation, DerivationResult)

def test_argon2derivation_valid_derivation_length():
    argon2_config = _generate_valid_argon2config_low()
    derivation = derive_argon2id(b"secret", argon2_config)
    assert len(derivation.key) == argon2_config.hash_len

def test_argon2derivation_valid_salt_length():
    argon2_config = _generate_valid_argon2config_low()
    derivation = derive_argon2id(b"secret", argon2_config)
    assert len(derivation.salt) == 16

def test_argon2derivation_different_derivations():
    argon2_config = _generate_valid_argon2config_low()
    derivation1 = derive_argon2id(b"secret", argon2_config)
    derivation2 = derive_argon2id(b"secret", argon2_config)
    assert derivation1.key != derivation2.key
    assert derivation1.salt != derivation2.salt

def test_argon2derivation_preserve_configuration():
    argon2_config = _generate_valid_argon2config_low()
    derivation = derive_argon2id(b"secret", argon2_config)
    assert argon2_config == derivation.parameters

def test_argon2derivation_raises_argon2exception():
    with patch(
        "kdf_tool.argon2_derivation.hash_secret_raw",
        side_effect=HashingError("Simulated hashing error")
    ):
        with pytest.raises(Argon2DerivationException) as exc_info:
            derive_argon2id(b"secret", _generate_valid_argon2config_low())

    assert isinstance(exc_info.value.__cause__, HashingError)