import pytest

from kdf_tool import HKDFDerivationRequest, CombinedDerivationResult, \
                     DerivationContext, HKDFDerivationResult, \
                     Argon2ConfigBuilder, Argon2DerivationResult


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
