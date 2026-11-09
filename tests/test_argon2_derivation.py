from kdf_tool.argon2_derivation import _generate_salt


def test_generate_salt_returns_bytes():
    salt = _generate_salt()
    assert isinstance(salt, bytes)


def test_generate_salt_has_correct_length():
    salt = _generate_salt()
    assert len(salt) == 16


def test_generate_salt_generates_different_values():
    salt_1 = _generate_salt()
    salt_2 = _generate_salt()
    assert salt_1 != salt_2