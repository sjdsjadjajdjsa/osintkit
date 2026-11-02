from osintkit import passwords_offline


def test_known_password_has_a_rank():
    assert passwords_offline.check("password") == 1


def test_case_insensitive():
    assert passwords_offline.check("PASSWORD") == 1


def test_unknown_password_is_none():
    assert passwords_offline.check("kR7#vQ2m!Xp9$Lw4") is None


def test_list_has_expected_size():
    assert passwords_offline.size() > 9000
