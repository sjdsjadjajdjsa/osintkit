import pytest

from osintkit.errors import TargetParseError
from osintkit.targets import detect_type, normalise, resolve


@pytest.mark.parametrize(
    "raw,kind",
    [
        ("alice@example.com", "email"),
        ("example.com", "domain"),
        ("alice", "username"),
        ("alice-ops", "username"),
        ("Example Ltd", "company"),
        ("Acme Inc", "company"),
    ],
)
def test_detects_expected_type(raw, kind):
    assert detect_type(raw) == kind


def test_normalises_scheme_and_www():
    assert normalise("https://www.Example.com/path/") == "Example.com"
    assert normalise("  <example.com> ") == "example.com"


def test_resolve_honours_declared_type():
    assert resolve("alice", "username") == ("alice", "username")


def test_declared_type_is_validated():
    with pytest.raises(TargetParseError):
        resolve("not an email", "email")


def test_unknown_declared_type_rejected():
    with pytest.raises(TargetParseError):
        resolve("example.com", "phone")


def test_empty_target_rejected():
    with pytest.raises(TargetParseError):
        resolve("   ")


def test_undetectable_target_rejected():
    with pytest.raises(TargetParseError):
        resolve("hello world!!")
