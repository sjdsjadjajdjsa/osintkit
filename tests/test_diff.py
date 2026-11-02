from osintkit.diff import compare, is_empty
from osintkit.models import Analysis, Report


def report(risk="low", breaches=(), subdomains=(), collectors=()):
    return Report(
        target="example.com",
        target_type="domain",
        collectors=list(collectors),
        analysis=Analysis(
            summary="s",
            breaches=[{"name": name} for name in breaches],
            subdomains=list(subdomains),
            risk_level=risk,
        ),
    )


def test_detects_added_and_removed_breaches():
    result = compare(report(breaches=["Acme", "Beta"]), report(breaches=["Beta", "Gamma"]))
    assert result["breaches"]["added"] == ["Gamma"]
    assert result["breaches"]["removed"] == ["Acme"]
    assert result["breaches"]["unchanged"] == 1


def test_detects_subdomain_changes_case_insensitively():
    result = compare(report(subdomains=["a.example.com"]), report(subdomains=["b.example.com"]))
    assert result["subdomains"]["added"] == ["b.example.com"]
    assert result["subdomains"]["removed"] == ["a.example.com"]


def test_risk_direction():
    assert compare(report("low"), report("high"))["risk_rose"] is True
    assert compare(report("high"), report("low"))["risk_fell"] is True
    assert compare(report("high"), report("high"))["risk_rose"] is False


def test_identical_reports_are_empty():
    same = report("medium", breaches=["Acme"], subdomains=["a.example.com"])
    assert is_empty(compare(same, same)) is True


def test_missing_analysis_is_tolerated():
    old = report()
    new = report()
    new.analysis = None
    result = compare(old, new)
    assert result["risk"]["new"] is None
    assert is_empty(result) is True
