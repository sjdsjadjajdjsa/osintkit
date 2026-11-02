from osintkit import confidence
from osintkit.models import CollectorResult


def result(name, data):
    return CollectorResult(collector=name, target="t", target_type="domain", data=data)


def test_no_sources_is_low():
    assert set(confidence.derive([]).values()) == {"low"}


def test_single_source_is_medium():
    assert confidence.derive([result("dns_records", {"A": ["1"]})])["infrastructure"] == "medium"


def test_two_sources_is_high():
    derived = confidence.derive(
        [result("dns_records", {"A": ["1"]}), result("whois_registration", {"registrar": "x"})]
    )
    assert derived["infrastructure"] == "high"


def test_breach_rows_drive_confidence():
    assert confidence.derive([result("breach_index", [{"name": "A"}])])["breaches"] == "medium"
    assert confidence.derive([result("breach_index", [{"name": "A"}, {"name": "B"}])])["breaches"] == "high"


def test_model_may_be_more_pessimistic():
    derived = {"breaches": "high"}
    assert confidence.apply({"breaches": "low"}, derived)["breaches"] == "low"


def test_model_cannot_exceed_evidence():
    derived = {"breaches": "medium"}
    assert confidence.apply({"breaches": "high"}, derived)["breaches"] == "medium"


def test_missing_or_junk_values_fall_back():
    out = confidence.apply({"breaches": "nonsense", "accounts": None}, {"breaches": "high"})
    assert out["breaches"] == "high"
    assert out["accounts"] == "low"
