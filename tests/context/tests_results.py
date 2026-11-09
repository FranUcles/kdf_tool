import pytest
from dataclasses import FrozenInstanceError
from types import MappingProxyType

from kdf_tool import HKDFDerivationRequest, CombinedDerivationResult, HKDFDerivationResult

@pytest.fixture
def valid_keys():
    return {
        "encryption": HKDFDerivationResult(
            key=b"A" * 32,
            length=32,
            hash_algorithm="sha256"
        ),
        "authentication": HKDFDerivationResult(
            key=b"B" * 64,
            length=64,
            hash_algorithm="sha256"
        )
    }


@pytest.fixture
def valid_combined_result(argon2_result, valid_requests, valid_keys):
    return CombinedDerivationResult(
        argon2_result=argon2_result,
        hkdf_salt=b"hkdf-salt",
        hash_algorithm="sha256",
        requests=valid_requests,
        keys=valid_keys
    )


# --------------------------------------------------
# Valid construction
# --------------------------------------------------

def test_combined_result_valid(valid_combined_result):
    result = valid_combined_result

    assert result.argon2_result is not None
    assert result.hkdf_salt == b"hkdf-salt"
    assert result.hash_algorithm == "sha256"
    assert len(result.requests) == 2
    assert result.keys["encryption"].key == b"A" * 32
    assert result.keys["authentication"].key == b"B" * 64


def test_combined_result_with_none_salt(
    argon2_result, valid_requests, valid_keys
):
    result = CombinedDerivationResult(
        argon2_result=argon2_result,
        hkdf_salt=None,
        hash_algorithm="sha256",
        requests=valid_requests,
        keys=valid_keys
    )

    assert result.hkdf_salt is None


def test_combined_result_preserves_request_order(valid_combined_result):
    ids = [request.id for request in valid_combined_result.requests]

    assert ids == ["encryption", "authentication"]


# --------------------------------------------------
# Frozen and immutable behavior
# --------------------------------------------------

def test_combined_result_is_frozen(valid_combined_result):
    with pytest.raises(FrozenInstanceError):
        valid_combined_result.hash_algorithm = "sha512"


def test_combined_result_keys_is_mapping_proxy(valid_combined_result):
    assert isinstance(valid_combined_result.keys, MappingProxyType)


def test_combined_result_keys_cannot_be_modified(valid_combined_result):
    with pytest.raises(TypeError):
        valid_combined_result.keys["new-key"] = valid_combined_result.keys[
            "encryption"
        ]


def test_combined_result_keys_does_not_share_original_mapping(
    argon2_result, valid_requests, valid_keys
):
    result = CombinedDerivationResult(
        argon2_result=argon2_result,
        hkdf_salt=None,
        hash_algorithm="sha256",
        requests=valid_requests,
        keys=valid_keys
    )

    valid_keys.clear()

    assert len(result.keys) == 2


# --------------------------------------------------
# argon2_result validation
# --------------------------------------------------

@pytest.mark.parametrize("value", [None, b"test", "result", 123])
def test_combined_result_invalid_argon2_result_type(
    value, valid_requests, valid_keys
):
    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=value,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=valid_keys
        )


# --------------------------------------------------
# hkdf_salt validation
# --------------------------------------------------

@pytest.mark.parametrize(
    "salt",
    ["salt", 123, 1.5, [], {}, bytearray(b"salt")]
)
def test_combined_result_invalid_salt_type(
    argon2_result, valid_requests, valid_keys, salt
):
    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=salt,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=valid_keys
        )


# --------------------------------------------------
# hash_algorithm validation
# --------------------------------------------------

@pytest.mark.parametrize(
    "algorithm",
    [None, 123, b"sha256", []]
)
def test_combined_result_invalid_hash_algorithm_type(
    argon2_result, valid_requests, valid_keys, algorithm
):
    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm=algorithm,
            requests=valid_requests,
            keys=valid_keys
        )


@pytest.mark.parametrize("algorithm", ["", "md5", "sha1", "invalid"])
def test_combined_result_invalid_hash_algorithm_value(
    argon2_result, valid_requests, valid_keys, algorithm
):
    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm=algorithm,
            requests=valid_requests,
            keys=valid_keys
        )


# --------------------------------------------------
# requests validation
# --------------------------------------------------

@pytest.mark.parametrize("requests", [None, [], {}, "requests", 123])
def test_combined_result_invalid_requests_type(
    argon2_result, valid_keys, requests
):
    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=requests,
            keys=valid_keys
        )


def test_combined_result_empty_requests(argon2_result):
    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=(),
            keys={}
        )


def test_combined_result_invalid_request_element(
    argon2_result, valid_keys
):
    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=("invalid-request",), # type: ignore
            keys=valid_keys
        )


def test_combined_result_duplicate_request_ids(
    argon2_result, valid_keys
):
    requests = (
        HKDFDerivationRequest("encryption", 32, b"first"),
        HKDFDerivationRequest("encryption", 64, b"second")
    )

    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=requests,
            keys=valid_keys
        )


# --------------------------------------------------
# keys validation
# --------------------------------------------------

@pytest.mark.parametrize("keys", [None, [], (), "keys", 123])
def test_combined_result_invalid_keys_type(
    argon2_result, valid_requests, keys
):
    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=keys
        )


def test_combined_result_missing_key(
    argon2_result, valid_requests, valid_keys
):
    keys = {"encryption": valid_keys["encryption"]}

    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=keys
        )


def test_combined_result_unexpected_key(
    argon2_result, valid_requests, valid_keys
):
    keys = {
        **valid_keys,
        "unexpected": valid_keys["encryption"]
    }

    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=keys
        )


def test_combined_result_invalid_key_result_type(
    argon2_result, valid_requests
):
    keys = {
        "encryption": b"not-a-result",
        "authentication": HKDFDerivationResult(
            key=b"B" * 64,
            length=64,
            hash_algorithm="sha256"
        )
    }

    with pytest.raises(TypeError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=keys
        )


def test_combined_result_incorrect_key_length(
    argon2_result, valid_requests, valid_keys
):
    keys = {
        **valid_keys,
        "encryption": HKDFDerivationResult(
            key=b"A" * 16,
            length=16,
            hash_algorithm="sha256"
        )
    }

    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=keys
        )


def test_combined_result_incorrect_key_algorithm(
    argon2_result, valid_requests, valid_keys
):
    keys = {
        **valid_keys,
        "encryption": HKDFDerivationResult(
            key=b"A" * 32,
            length=32,
            hash_algorithm="sha512"
        )
    }

    with pytest.raises(ValueError):
        CombinedDerivationResult(
            argon2_result=argon2_result,
            hkdf_salt=None,
            hash_algorithm="sha256",
            requests=valid_requests,
            keys=keys
        )