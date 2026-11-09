import pytest

import pytest

from kdf_tool import (
    Argon2Config,
    Argon2ConfigBuilder,
)
from argon2.low_level import ARGON2_VERSION


def test_basic_profile():
    config = Argon2ConfigBuilder().set_profile("BASIC").build()

    assert config.profile == "BASIC"
    assert config.time_cost == 3
    assert config.memory_cost == 262144
    assert config.parallelism == 4
    assert config.hash_len == 32
    assert config.version == ARGON2_VERSION


def test_high_profile():
    config = Argon2ConfigBuilder().set_profile("HIGH").build()

    assert config.memory_cost == 524288


def test_max_profile():
    config = Argon2ConfigBuilder().set_profile("MAX").build()

    assert config.memory_cost == 1048576


def test_custom_profile():
    config = (
        Argon2ConfigBuilder()
        .set_profile("BASIC")
        .set_memory_cost(524288)
        .build()
    )

    assert config.profile == "CUSTOM"
    assert config.memory_cost == 524288


def test_invalid_profile():
    with pytest.raises(ValueError):
        Argon2ConfigBuilder().set_profile("INVALID")


def test_invalid_time_cost():
    with pytest.raises(ValueError):
        Argon2ConfigBuilder().set_time_cost(0)


def test_memory_limit():
    with pytest.raises(ValueError):
        Argon2ConfigBuilder().set_memory_cost(3000000)


def test_boolean_is_not_valid_integer():
    with pytest.raises(TypeError):
        Argon2ConfigBuilder().set_parallelism(True)


def test_hash_len_minimum():
    with pytest.raises(ValueError):
        Argon2ConfigBuilder().set_hash_len(2)


def test_missing_configuration():
    with pytest.raises(ValueError):
        Argon2ConfigBuilder().build()


def test_config_is_immutable():
    config = Argon2ConfigBuilder().set_profile("BASIC").build()

    with pytest.raises(AttributeError):
        config.memory_cost = 524288 # type: ignore


def test_direct_invalid_configuration():
    with pytest.raises(ValueError):
        Argon2Config(
            profile="BASIC",
            time_cost=0,
            memory_cost=262144,
            parallelism=4,
            hash_len=32,
            version=ARGON2_VERSION,
        )