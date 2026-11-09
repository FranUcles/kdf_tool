
import pytest
from dataclasses import FrozenInstanceError
from kdf_tool import (
    HKDFDerivationResult,
    derive_hkdf,
    AVAILABLE_HASH_ALGORITHMS
)

def test_derive_hkdf_invalid_ikm_type():
    with pytest.raises(TypeError):
        derive_hkdf(
            ikm="invalid",  # type: ignore
            length=32
        )


def test_derive_hkdf_empty_ikm():
    with pytest.raises(ValueError):
        derive_hkdf(
            ikm=b"",
            length=32
        )


def test_derive_hkdf_invalid_length_type():
    with pytest.raises(TypeError):
        derive_hkdf(
            ikm=b"input key material",
            length=True  # type: ignore
        )


@pytest.mark.parametrize("length", [0, -1])
def test_derive_hkdf_invalid_length(length):
    with pytest.raises(ValueError):
        derive_hkdf(
            ikm=b"input key material",
            length=length
        )


def test_derive_hkdf_invalid_salt_type():
    with pytest.raises(TypeError):
        derive_hkdf(
            ikm=b"input key material",
            length=32,
            salt="invalid"  # type: ignore
        )


def test_derive_hkdf_invalid_info_type():
    with pytest.raises(TypeError):
        derive_hkdf(
            ikm=b"input key material",
            length=32,
            info="invalid"  # type: ignore
        )


def test_derive_hkdf_invalid_hash_algorithm_type():
    with pytest.raises(TypeError):
        derive_hkdf(
            ikm=b"input key material",
            length=32,
            hash_algorithm=123  # type: ignore
        )


def test_derive_hkdf_empty_hash_algorithm():
    with pytest.raises(ValueError):
        derive_hkdf(
            ikm=b"input key material",
            length=32,
            hash_algorithm=""
        )


@pytest.mark.parametrize(
    "hash_algorithm",
    ["md5", "sha1", "sha3_256", "invalid"]
)
def test_derive_hkdf_unsupported_hash_algorithm(hash_algorithm):
    with pytest.raises(ValueError):
        derive_hkdf(
            ikm=b"input key material",
            length=32,
            hash_algorithm=hash_algorithm
        )


def test_derive_hkdf_length_exceeds_maximum():
    with pytest.raises(ValueError):
        derive_hkdf(
            ikm=b"input key material",
            length=255 * 32 + 1,
            hash_algorithm="sha256"
        )

def test_hkdf_derivation_result_valid():
    result = HKDFDerivationResult(
        key=b"\x01" * 32,
        length=32,
        hash_algorithm="sha256"
    )

    assert result.key == b"\x01" * 32
    assert result.length == 32
    assert result.hash_algorithm == "sha256"


@pytest.mark.parametrize("hash_algorithm", AVAILABLE_HASH_ALGORITHMS)
def test_hkdf_derivation_result_supported_algorithms(hash_algorithm):
    result = HKDFDerivationResult(
        key=b"\x01" * 32,
        length=32,
        hash_algorithm=hash_algorithm
    )

    assert result.hash_algorithm == hash_algorithm


def test_hkdf_derivation_result_invalid_key_type():
    with pytest.raises(TypeError):
        HKDFDerivationResult(
            key="invalid",  # type: ignore
            length=7,
            hash_algorithm="sha256"
        )


def test_hkdf_derivation_result_empty_key():
    with pytest.raises(ValueError):
        HKDFDerivationResult(
            key=b"",
            length=0,
            hash_algorithm="sha256"
        )


def test_hkdf_derivation_result_invalid_length_type():
    with pytest.raises(TypeError):
        HKDFDerivationResult(
            key=b"\x01",
            length=True,  # type: ignore
            hash_algorithm="sha256"
        )


def test_hkdf_derivation_result_negative_length():
    with pytest.raises(ValueError):
        HKDFDerivationResult(
            key=b"\x01",
            length=-1,
            hash_algorithm="sha256"
        )


def test_hkdf_derivation_result_incorrect_length():
    with pytest.raises(ValueError):
        HKDFDerivationResult(
            key=b"\x01" * 32,
            length=16,
            hash_algorithm="sha256"
        )


def test_hkdf_derivation_result_invalid_hash_algorithm_type():
    with pytest.raises(TypeError):
        HKDFDerivationResult(
            key=b"\x01" * 32,
            length=32,
            hash_algorithm=123  # type: ignore
        )


def test_hkdf_derivation_result_empty_hash_algorithm():
    with pytest.raises(ValueError):
        HKDFDerivationResult(
            key=b"\x01" * 32,
            length=32,
            hash_algorithm=""
        )


@pytest.mark.parametrize("hash_algorithm", ["md5", "sha1", "sha3_256", "invalid"])
def test_hkdf_derivation_result_unsupported_hash_algorithm(hash_algorithm):
    with pytest.raises(ValueError):
        HKDFDerivationResult(
            key=b"\x01" * 32,
            length=32,
            hash_algorithm=hash_algorithm
        )


def test_hkdf_derivation_result_is_immutable():
    result = HKDFDerivationResult(
        key=b"\x01" * 32,
        length=32,
        hash_algorithm="sha256"
    )

    with pytest.raises(FrozenInstanceError):
        result.key = b"\x02" * 32  # type: ignore

@pytest.mark.parametrize("hash_algorithm, expected_length", [
    ("sha256", 32),
    ("sha384", 48),
    ("sha512", 64),
])
def test_derive_hkdf_valid(hash_algorithm, expected_length):
    result = derive_hkdf(
        ikm=b"input key material",
        length=expected_length,
        hash_algorithm=hash_algorithm
    )

    assert isinstance(result, HKDFDerivationResult)
    assert isinstance(result.key, bytes)
    assert len(result.key) == expected_length
    assert result.length == expected_length
    assert result.hash_algorithm == hash_algorithm

def test_derive_hkdf_rfc5869_case_1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    result = derive_hkdf(
        ikm=ikm,
        length=42,
        salt=salt,
        info=info,
        hash_algorithm="sha256"
    )

    assert result.key == expected_okm
    assert result.length == 42
    assert result.hash_algorithm == "sha256"