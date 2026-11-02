from osintkit.models import CollectorResult
from osintkit.normalise import merge_breaches


def result(source, entries):
    return CollectorResult(collector=source, target="a@b.co", target_type="email", data=entries)


def test_duplicates_across_sources_merge_with_union():
    results = [
        result(
            "hibp_breaches",
            [{"name": "Acme", "date": "2019-01-01", "data_types": ["Emails"], "source": "haveibeenpwned"}],
        ),
        result(
            "xposed_or_not",
            [{"name": "acme", "date": "2020-05-05", "data_types": ["Passwords"], "source": "xposedornot"}],
        ),
    ]
    kept, duplicates = merge_breaches(results)
    assert duplicates == 1
    index = next(r for r in kept if r.collector == "breach_index")
    assert index.data[0]["data_types"] == ["Emails", "Passwords"]
    assert index.data[0]["sources"] == ["haveibeenpwned", "xposedornot"]
    assert index.data[0]["date"] == "2019-01-01"


def test_distinct_breaches_stay_separate():
    results = [result("xposed_or_not", [{"name": "Acme"}, {"name": "Beta"}])]
    kept, duplicates = merge_breaches(results)
    assert duplicates == 0
    assert len(kept[0].data) == 2


def test_sorted_by_exposure_then_name():
    results = [result("xposed_or_not", [{"name": "Zeta"}, {"name": "Alpha", "data_types": ["Emails"]}])]
    kept, _ = merge_breaches(results)
    assert [row["name"] for row in kept[0].data] == ["Alpha", "Zeta"]


def test_skipped_breach_sources_are_preserved():
    results = [
        CollectorResult(
            collector="hibp_breaches", target="t", target_type="email", ok=False, skipped=True, note="no key"
        ),
        result("xposed_or_not", [{"name": "Acme"}]),
    ]
    kept, _ = merge_breaches(results)
    assert [r.collector for r in kept] == ["breach_index", "hibp_breaches"]


def test_no_breach_sources_is_a_noop():
    results = [result("dns_records", {"A": ["1.2.3.4"]})]
    kept, duplicates = merge_breaches(results)
    assert kept == results and duplicates == 0


def test_empty_breach_data_is_a_noop():
    results = [result("xposed_or_not", [])]
    kept, duplicates = merge_breaches(results)
    assert duplicates == 0
    assert kept == results
