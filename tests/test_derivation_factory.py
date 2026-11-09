import pytest

from kdf_tool.derivation_factory import HKDFDerivationRequest


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