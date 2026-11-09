import pytest

from kdf_tool.derivation_context import HKDFDerivationRequest, CombinedDerivationResult, DerivationContext
from dataclasses import FrozenInstanceError
from types import MappingProxyType
from kdf_tool.hkdf_derivation import HKDFDerivationResult
from kdf_tool.argon2_config import Argon2Config, Argon2ConfigBuilder
from kdf_tool.argon2_derivation import derive_argon2id, Argon2DerivationResult


def test_hkdf_request_valid():
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"my-app/encryption"
    )

    assert request.id == "encryption"
    assert request.length == 32
    assert request.info == b"my-app/encryption"


def test_hkdf_request_empty_info():
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b""
    )

    assert request.info == b""


def test_hkdf_request_is_frozen():
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"my-app/encryption"
    )

    with pytest.raises(AttributeError):
        request.length = 64 # type: ignore

@pytest.mark.parametrize("id", [None, 123, b"encryption", [], {}])
def test_hkdf_request_invalid_id_type(id):
    with pytest.raises(TypeError):
        HKDFDerivationRequest(id=id, length=32, info=b"test")


@pytest.mark.parametrize("id", ["", " ", "   ", "\t", "\n"])
def test_hkdf_request_invalid_id_value(id):
    with pytest.raises(ValueError):
        HKDFDerivationRequest(id=id, length=32, info=b"test")


@pytest.mark.parametrize(
    "id",
    [" encryption", "encryption ", " encryption "]
)
def test_hkdf_request_id_with_surrounding_whitespace(id):
    with pytest.raises(ValueError):
        HKDFDerivationRequest(id=id, length=32, info=b"test")

@pytest.mark.parametrize("length", [None, "32", 32.0, b"32", True, False])
def test_hkdf_request_invalid_length_type(length):
    with pytest.raises(TypeError):
        HKDFDerivationRequest(
            id="encryption",
            length=length,
            info=b"test"
        )


@pytest.mark.parametrize("length", [0, -1, -32])
def test_hkdf_request_invalid_length_value(length):
    with pytest.raises(ValueError):
        HKDFDerivationRequest(
            id="encryption",
            length=length,
            info=b"test"
        )

@pytest.mark.parametrize(
    "info",
    [None, "my-app/encryption", 123, [], {}, bytearray(b"test")]
)
def test_hkdf_request_invalid_info_type(info):
    with pytest.raises(TypeError):
        HKDFDerivationRequest(
            id="encryption",
            length=32,
            info=info
        )

@pytest.fixture
def argon2_result():
    config = Argon2ConfigBuilder().set_time_cost(1)\
            .set_memory_cost(8).set_parallelism(1)\
            .set_hash_len(4).build()
    return derive_argon2id(b"test-secret", config)


@pytest.fixture
def valid_requests():
    return (
        HKDFDerivationRequest(
            id="encryption",
            length=32,
            info=b"app/encryption"
        ),
        HKDFDerivationRequest(
            id="authentication",
            length=64,
            info=b"app/authentication"
        )
    )


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

def generate_argon2_result() -> Argon2DerivationResult:
    return Argon2DerivationResult(key=b"0"*4, salt=b"0"*20, parameters=Argon2ConfigBuilder().set_time_cost(1)\
            .set_memory_cost(8).set_parallelism(1)\
            .set_hash_len(4).build())

@pytest.mark.parametrize(
    ("hash_algorithm", "prk_length"),
    [
        ("sha256", 32),
        ("sha384", 48),
        ("sha512", 64),
    ]
)
def test_derivation_context_valid_construction(
    hash_algorithm,
    prk_length
):
    prk = b"P" * prk_length
    salt = b"test-salt"

    context = DerivationContext(
        prk=prk,
        argon2_result=generate_argon2_result(),
        hash_algorithm=hash_algorithm,
        hkdf_salt=salt
    )

    assert context._prk == prk
    assert context._hash_algorithm == hash_algorithm
    assert context._hkdf_salt == salt
    assert context._requests == []
    assert context._keys == {}
    assert context._closed is False


def test_derivation_context_without_salt():
    context = DerivationContext(
        prk=b"P" * 32,
        argon2_result=generate_argon2_result(),
        hash_algorithm="sha256"
    )

    assert context._hkdf_salt is None


def test_derivation_context_with_empty_salt():
    context = DerivationContext(
        prk=b"P" * 32,
        argon2_result=generate_argon2_result(),
        hash_algorithm="sha256",
        hkdf_salt=b""
    )

    assert context._hkdf_salt == b""


def test_derivation_context_invalid_prk_type():
    with pytest.raises(TypeError):
        DerivationContext(
            prk="invalid",  # type: ignore
            hash_algorithm="sha256"
        )


def test_derivation_context_empty_prk():
    with pytest.raises(ValueError):
        DerivationContext(
            prk=b"",
            argon2_result=generate_argon2_result(),
            hash_algorithm="sha256"
        )


def test_derivation_context_invalid_hash_algorithm_type():
    with pytest.raises(TypeError):
        DerivationContext(
            prk=b"P" * 32,
            hash_algorithm=123  # type: ignore
        )


@pytest.mark.parametrize(
    "hash_algorithm",
    ["", "md5", "sha1", "sha3_256", "invalid"]
)
def test_derivation_context_unsupported_hash_algorithm(hash_algorithm):
    with pytest.raises(ValueError):
        DerivationContext(
            prk=b"P" * 32,
            argon2_result=generate_argon2_result(),
            hash_algorithm=hash_algorithm
        )


@pytest.mark.parametrize(
    ("hash_algorithm", "prk_length"),
    [
        ("sha256", 31),
        ("sha256", 33),
        ("sha384", 32),
        ("sha512", 48),
    ]
)
def test_derivation_context_invalid_prk_length(
    hash_algorithm,
    prk_length
):
    with pytest.raises(ValueError):
        DerivationContext(
            prk=b"P" * prk_length,
            argon2_result=generate_argon2_result(),
            hash_algorithm=hash_algorithm
        )


@pytest.mark.parametrize(
    "hkdf_salt",
    ["invalid", 123, [], {}]
)
def test_derivation_context_invalid_salt_type(hkdf_salt):
    with pytest.raises(TypeError):
        DerivationContext(
            prk=b"P" * 32,
            hash_algorithm="sha256",
            hkdf_salt=hkdf_salt  # type: ignore
        )


@pytest.fixture
def valid_context():
    return DerivationContext(
        prk=b"P" * 32,
        argon2_result=generate_argon2_result(),
        hash_algorithm="sha256"
    )


def test_derive_key_valid_request(valid_context):
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    result = valid_context.derive_key(request)

    assert isinstance(result, HKDFDerivationResult)
    assert result.length == 32
    assert result.hash_algorithm == "sha256"
    assert len(result.key) == 32


def test_derive_key_registers_request_and_result(valid_context):
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    result = valid_context.derive_key(request)

    assert valid_context._requests == [request]
    assert valid_context._keys == {"encryption": result}


def test_derive_key_multiple_requests(valid_context):
    request1 = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    request2 = HKDFDerivationRequest(
        id="authentication",
        length=64,
        info=b"app/authentication"
    )

    result1 = valid_context.derive_key(request1)
    result2 = valid_context.derive_key(request2)

    assert result1.key != result2.key
    assert len(valid_context._requests) == 2
    assert len(valid_context._keys) == 2


def test_derive_key_duplicate_id(valid_context):
    request1 = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    request2 = HKDFDerivationRequest(
        id="encryption",
        length=64,
        info=b"app/other-encryption"
    )

    valid_context.derive_key(request1)

    with pytest.raises(ValueError):
        valid_context.derive_key(request2)

    assert len(valid_context._requests) == 1
    assert len(valid_context._keys) == 1


def test_derive_key_invalid_request_type(valid_context):
    with pytest.raises(TypeError):
        valid_context.derive_key("invalid")  # type: ignore


def test_derive_key_closed_context(valid_context):
    valid_context._closed = True

    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    with pytest.raises(ValueError, match="context is closed"):
        valid_context.derive_key(request)

    assert valid_context._requests == []
    assert valid_context._keys == {}


def test_get_key_valid_id(valid_context):
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    expected_result = valid_context.derive_key(request)

    result = valid_context.get_key("encryption")

    assert result is expected_result


def test_get_key_invalid_id_type(valid_context):
    with pytest.raises(TypeError):
        valid_context.get_key(123)  # type: ignore


def test_get_key_empty_id(valid_context):
    with pytest.raises(ValueError):
        valid_context.get_key("")


def test_get_key_nonexistent_id(valid_context):
    with pytest.raises(KeyError):
        valid_context.get_key("nonexistent")


def test_get_key_closed_context(valid_context):
    valid_context._closed = True

    with pytest.raises(ValueError, match="context is closed"):
        valid_context.get_key("encryption")


def test_get_result_valid(valid_context):
    request1 = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    request2 = HKDFDerivationRequest(
        id="authentication",
        length=64,
        info=b"app/authentication"
    )

    valid_context.derive_key(request1)
    valid_context.derive_key(request2)

    result = valid_context.get_result()

    assert isinstance(result, CombinedDerivationResult)
    assert result.argon2_result is valid_context._argon2_result
    assert result.hash_algorithm == "sha256"
    assert result.requests == (request1, request2)
    assert set(result.keys.keys()) == {"encryption", "authentication"}


def test_get_result_without_derived_keys(valid_context):
    with pytest.raises(ValueError, match="no keys have been derived"):
        valid_context.get_result()


def test_get_result_closed_context(valid_context):
    valid_context._closed = True

    with pytest.raises(ValueError, match="context is closed"):
        valid_context.get_result()


def test_get_result_is_independent_from_context(valid_context):
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    valid_context.derive_key(request)
    result = valid_context.get_result()

    another_request = HKDFDerivationRequest(
        id="authentication",
        length=32,
        info=b"app/authentication"
    )

    valid_context.derive_key(another_request)

    assert len(result.requests) == 1
    assert len(result.keys) == 1
    assert len(valid_context._requests) == 2
    assert len(valid_context._keys) == 2


def test_close_context(valid_context):
    valid_context.close()

    assert valid_context._closed is True
    assert valid_context._prk is None


def test_close_context_idempotent(valid_context):
    valid_context.close()
    valid_context.close()

    assert valid_context._closed is True
    assert valid_context._prk is None


def test_close_context_after_derivation(valid_context):
    request = HKDFDerivationRequest(
        id="encryption",
        length=32,
        info=b"app/encryption"
    )

    valid_context.derive_key(request)
    valid_context.close()

    assert valid_context._closed is True
    assert valid_context._prk is None
    assert len(valid_context._requests) == 1
    assert len(valid_context._keys) == 1


def test_context_manager_returns_context(valid_context):
    with valid_context as context:
        assert context is valid_context
        assert context._closed is False


def test_context_manager_closes_context(valid_context):
    with valid_context:
        pass

    assert valid_context._closed is True
    assert valid_context._prk is None


def test_context_manager_closes_after_exception(valid_context):
    with pytest.raises(RuntimeError):
        with valid_context:
            raise RuntimeError("test exception")

    assert valid_context._closed is True
    assert valid_context._prk is None


def test_context_manager_cannot_reopen_closed_context(valid_context):
    valid_context.close()

    with pytest.raises(ValueError, match="context is closed"):
        with valid_context:
            pass
