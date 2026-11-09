import pytest
from kdf_tool.hkdf.derivation import _hkdf_expand

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