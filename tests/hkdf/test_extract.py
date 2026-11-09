import pytest
from kdf_tool.hkdf.derivation import _hkdf_extract

AVAILABLE_HASH_ALGORITHMS = [
    ("sha256", 32),
    ("sha384", 48),
    ("sha512", 64),
]

def _generate_valid_ikm() -> bytes:
    return b"test input keying material"

@pytest.mark.parametrize(
    "hash_algorithm, expected_length",
    AVAILABLE_HASH_ALGORITHMS
)
def test_hkdf_extract_returns_bytes(hash_algorithm, expected_length):
    prk = _hkdf_extract(ikm=_generate_valid_ikm(), hash_algorithm=hash_algorithm)
    assert isinstance(prk, bytes)
    assert len(prk) == expected_length

@pytest.mark.parametrize(
    "hash_algorithm, expected_length",
    AVAILABLE_HASH_ALGORITHMS
)
def test_hkdf_extract_with_none_salt(hash_algorithm, expected_length):
    prk = _hkdf_extract(
        ikm=_generate_valid_ikm(),
        hash_algorithm=hash_algorithm,
        salt=None
    )

    assert isinstance(prk, bytes)
    assert len(prk) == expected_length


@pytest.mark.parametrize(
    "hash_algorithm",
    ["sha256", "sha384", "sha512"]
)
def test_hkdf_extract_empty_salt_equals_none(hash_algorithm):
    ikm = _generate_valid_ikm()

    prk_none = _hkdf_extract(
        ikm=ikm,
        hash_algorithm=hash_algorithm,
        salt=None
    )

    prk_empty = _hkdf_extract(
        ikm=ikm,
        hash_algorithm=hash_algorithm,
        salt=b""
    )

    assert prk_none == prk_empty


def test_hkdf_extract_different_salts_produce_different_prks():
    ikm = _generate_valid_ikm()

    prk_1 = _hkdf_extract(
        ikm=ikm,
        hash_algorithm="sha256",
        salt=b"salt 1"
    )

    prk_2 = _hkdf_extract(
        ikm=ikm,
        hash_algorithm="sha256",
        salt=b"salt 2"
    )

    assert prk_1 != prk_2

@pytest.mark.parametrize("ikm", ["secret", 123, None, bytearray(b"secret")])
def test_hkdf_extract_invalid_ikm_type(ikm):
    with pytest.raises(TypeError):
        _hkdf_extract(
            ikm=ikm,
            hash_algorithm="sha256"
        )


def test_hkdf_extract_empty_ikm():
    with pytest.raises(ValueError):
        _hkdf_extract(
            ikm=b"",
            hash_algorithm="sha256"
        )


@pytest.mark.parametrize("salt", ["salt", 123, bytearray(b"salt")])
def test_hkdf_extract_invalid_salt_type(salt):
    with pytest.raises(TypeError):
        _hkdf_extract(
            ikm=_generate_valid_ikm(),
            hash_algorithm="sha256",
            salt=salt
        )


@pytest.mark.parametrize("hash_algorithm", [123, None, b"sha256"])
def test_hkdf_extract_invalid_hash_algorithm_type(hash_algorithm):
    with pytest.raises(TypeError):
        _hkdf_extract(
            ikm=_generate_valid_ikm(),
            hash_algorithm=hash_algorithm
        )


@pytest.mark.parametrize(
    "hash_algorithm",
    ["md5", "sha1", "sha3_256", "invalid", ""]
)
def test_hkdf_extract_unsupported_hash_algorithm(hash_algorithm):
    with pytest.raises(ValueError):
        _hkdf_extract(
            ikm=_generate_valid_ikm(),
            hash_algorithm=hash_algorithm
        )

# Test from the RFC 5869 with its test vectors
def test_hkdf_extract_rfc5869_case_1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")

    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )

    prk = _hkdf_extract(
        ikm=ikm,
        hash_algorithm="sha256",
        salt=salt
    )

    assert prk == expected_prk