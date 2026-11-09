
import pytest

from kdf_tool.hkdf_derivation import _hkdf_extract, _hkdf_expand


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

def test_hkdf_expand_invalid_prk_type():
    with pytest.raises(TypeError):
        _hkdf_expand("invalid", 32, b"", "sha256")  # type: ignore


def test_hkdf_expand_empty_prk():
    with pytest.raises(ValueError):
        _hkdf_expand(b"", 32, b"", "sha256")


def test_hkdf_expand_invalid_prk_length():
    with pytest.raises(ValueError):
        _hkdf_expand(b"\x01" * 31, 32, b"", "sha256")


def test_hkdf_expand_invalid_length_type():
    with pytest.raises(TypeError):
        _hkdf_expand(b"\x01" * 32, "32", b"", "sha256")  # type: ignore


@pytest.mark.parametrize("length", [True, False])
def test_hkdf_expand_boolean_length(length):
    with pytest.raises(TypeError):
        _hkdf_expand(b"\x01" * 32, length, b"", "sha256")


@pytest.mark.parametrize("length", [0, -1])
def test_hkdf_expand_non_positive_length(length):
    with pytest.raises(ValueError):
        _hkdf_expand(b"\x01" * 32, length, b"", "sha256")


def test_hkdf_expand_invalid_hash_algorithm_type():
    with pytest.raises(TypeError):
        _hkdf_expand(b"\x01" * 32, 32, b"", 123)  # type: ignore


@pytest.mark.parametrize(
    "hash_algorithm",
    ["md5", "sha1", "sha3_256", "invalid", ""],
)
def test_hkdf_expand_unsupported_hash_algorithm(hash_algorithm):
    with pytest.raises(ValueError):
        _hkdf_expand(b"\x01" * 32, 32, b"", hash_algorithm)

def test_hkdf_expand_empty_info():
    prk = b"\x01" * 32

    result = _hkdf_expand(prk, 32, b"", "sha256")

    assert isinstance(result, bytes)
    assert len(result) == 32


def test_hkdf_expand_different_info():
    prk = b"\x01" * 32

    result_1 = _hkdf_expand(prk, 32, b"encryption", "sha256")
    result_2 = _hkdf_expand(prk, 32, b"authentication", "sha256")

    assert result_1 != result_2


def test_hkdf_expand_invalid_info():
    prk = b"\x01" * 32

    with pytest.raises(TypeError):
        _hkdf_expand(prk, 32, "invalid", "sha256")  # type: ignore

@pytest.mark.parametrize(
    "length, expected_blocks",
    [
        (1, 1),
        (32, 1),
        (33, 2),
        (64, 2),
        (65, 3),
    ],
)
def test_hkdf_expand_block_count(length, expected_blocks):
    hash_length = 32
    prk = b"\x01" * hash_length

    result = _hkdf_expand(prk, length, b"", "sha256")

    assert len(result) == length
    assert expected_blocks == -(-length // hash_length)

def test_hkdf_expand_maximum_length():
    prk = b"\x01" * 32
    max_length = 255 * 32

    result = _hkdf_expand(prk, max_length, b"", "sha256")

    assert len(result) == max_length


def test_hkdf_expand_exceeding_maximum_length():
    prk = b"\x01" * 32
    max_length = 255 * 32

    with pytest.raises(ValueError):
        _hkdf_expand(prk, max_length + 1, b"", "sha256")

@pytest.mark.parametrize(
    "hash_algorithm, hash_length",
    [
        ("sha256", 32),
        ("sha384", 48),
        ("sha512", 64),
    ],
)
def test_hkdf_expand_supported_algorithms(hash_algorithm, hash_length):
    prk = b"\x01" * hash_length

    result = _hkdf_expand(
        prk,
        hash_length + 10,
        b"test-info",
        hash_algorithm,
    )

    assert isinstance(result, bytes)
    assert len(result) == hash_length + 10

def test_hkdf_expand_rfc5869_case_1():
    prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    result = _hkdf_expand(prk, 42, info, "sha256")

    assert result == expected_okm


def test_hkdf_expand_rfc5869_case_2():
    prk = bytes.fromhex(
        "06a6b88c5853361a06104c9ceb35b45c"
        "ef760014904671014a193f40c15fc244"
    )
    info = bytes.fromhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    expected_okm = bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )

    result = _hkdf_expand(prk, 82, info, "sha256")

    assert result == expected_okm


def test_hkdf_expand_rfc5869_case_3():
    prk = bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04"
    )
    expected_okm = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )

    result = _hkdf_expand(prk, 42, b"", "sha256")

    assert result == expected_okm