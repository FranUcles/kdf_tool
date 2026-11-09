import pytest
from kdf_tool import HKDFDerivationRequest, Argon2ConfigBuilder, derive_argon2id


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