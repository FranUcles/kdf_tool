
import pytest

from unittest.mock import Mock

import kdf_tool.context.factory as factory_module

from kdf_tool import DerivationFactory, DerivationContext, Argon2Config, Argon2DerivationResult
from kdf_tool.argon2.config import ARGON2_VERSION


@pytest.fixture
def valid_config():
    return Argon2Config(
        profile="CUSTOM",
        time_cost=1,
        memory_cost=8,
        parallelism=1,
        hash_len=32,
        version=ARGON2_VERSION
    )


@pytest.fixture
def valid_argon2_result():
    return Argon2DerivationResult(
        key=b"A" * 32,
        salt=b"S" * 16,
        parameters=Argon2Config(
            profile="CUSTOM",
            time_cost=1,
            memory_cost=8,
            parallelism=1,
            hash_len=32,
            version=ARGON2_VERSION
        )
    )


@pytest.fixture
def valid_prk():
    return b"P" * 32


def test_factory_creates_context(
    valid_config,
    valid_argon2_result,
    valid_prk,
    monkeypatch
):
    mock_argon2 = Mock(return_value=valid_argon2_result)
    mock_extract = Mock(return_value=valid_prk)

    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        mock_argon2
    )

    monkeypatch.setattr(
        factory_module,
        "_hkdf_extract",
        mock_extract
    )

    context = DerivationFactory.create(
        secret=b"test-secret",
        argon2_config=valid_config,
        hkdf_salt=b"test-salt",
        hash_algorithm="sha256"
    )

    assert isinstance(context, DerivationContext)
    assert context._prk == valid_prk
    assert context._argon2_result is valid_argon2_result
    assert context._hash_algorithm == "sha256"
    assert context._hkdf_salt == b"test-salt"

    mock_argon2.assert_called_once_with(
        secret=b"test-secret",
        config=valid_config
    )

    mock_extract.assert_called_once_with(
        ikm=valid_argon2_result.key,
        hash_algorithm="sha256",
        salt=b"test-salt"
    )


def test_factory_without_hkdf_salt(
    valid_config,
    valid_argon2_result,
    valid_prk,
    monkeypatch
):
    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        Mock(return_value=valid_argon2_result)
    )

    mock_extract = Mock(return_value=valid_prk)

    monkeypatch.setattr(
        factory_module,
        "_hkdf_extract",
        mock_extract
    )

    context = DerivationFactory.create(
        secret=b"test-secret",
        argon2_config=valid_config
    )

    assert context._hkdf_salt is None

    mock_extract.assert_called_once_with(
        ikm=valid_argon2_result.key,
        hash_algorithm="sha256",
        salt=None
    )


def test_factory_invalid_hash_algorithm_type(valid_config, monkeypatch):
    mock_argon2 = Mock()

    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        mock_argon2
    )

    with pytest.raises(TypeError):
        DerivationFactory.create(
            secret=b"test-secret",
            argon2_config=valid_config,
            hash_algorithm=123  # type: ignore
        )

    mock_argon2.assert_not_called()


@pytest.mark.parametrize(
    "hash_algorithm",
    ["", "md5", "sha1", "sha3_256", "invalid"]
)
def test_factory_unsupported_hash_algorithm(
    valid_config,
    hash_algorithm,
    monkeypatch
):
    mock_argon2 = Mock()

    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        mock_argon2
    )

    with pytest.raises(ValueError):
        DerivationFactory.create(
            secret=b"test-secret",
            argon2_config=valid_config,
            hash_algorithm=hash_algorithm
        )

    mock_argon2.assert_not_called()


@pytest.mark.parametrize(
    "hkdf_salt",
    ["invalid", 123, [], {}]
)
def test_factory_invalid_salt_type(
    valid_config,
    hkdf_salt,
    monkeypatch
):
    mock_argon2 = Mock()

    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        mock_argon2
    )

    with pytest.raises(TypeError):
        DerivationFactory.create(
            secret=b"test-secret",
            argon2_config=valid_config,
            hkdf_salt=hkdf_salt  # type: ignore
        )

    mock_argon2.assert_not_called()


def test_factory_propagates_argon2_exception(
    valid_config,
    monkeypatch
):
    mock_argon2 = Mock(side_effect=RuntimeError("Argon2 failure"))
    mock_extract = Mock()

    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        mock_argon2
    )

    monkeypatch.setattr(
        factory_module,
        "_hkdf_extract",
        mock_extract
    )

    with pytest.raises(RuntimeError, match="Argon2 failure"):
        DerivationFactory.create(
            secret=b"test-secret",
            argon2_config=valid_config
        )

    mock_extract.assert_not_called()


def test_factory_propagates_extract_exception(
    valid_config,
    valid_argon2_result,
    monkeypatch
):
    monkeypatch.setattr(
        factory_module,
        "derive_argon2id",
        Mock(return_value=valid_argon2_result)
    )

    mock_extract = Mock(side_effect=ValueError("Extract failure"))

    monkeypatch.setattr(
        factory_module,
        "_hkdf_extract",
        mock_extract
    )

    with pytest.raises(ValueError, match="Extract failure"):
        DerivationFactory.create(
            secret=b"test-secret",
            argon2_config=valid_config
        )
