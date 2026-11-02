from osintkit import verify
from osintkit.models import Analysis, CollectorResult


def result(name, data):
    return CollectorResult(collector=name, target="t", target_type="email", data=data)


def analysis(**kwargs):
    base = {"summary": "s", "risk_level": "low"}
    base.update(kwargs)
    return Analysis.model_validate(base)


def test_supported_claims_pass():
    results = [result("breach_index", [{"name": "Acme", "date": "2020-01-01"}])]
    check = analysis(breaches=[{"name": "Acme", "date": "2020-01-01"}])
    assert verify.claims(check, results) == []


def test_unknown_breach_is_flagged():
    results = [result("breach_index", [{"name": "Acme"}])]
    check = analysis(breaches=[{"name": "Invented"}])
    assert any("Invented" in issue for issue in verify.claims(check, results))


def test_wrong_date_is_flagged():
    results = [result("breach_index", [{"name": "Acme", "date": "2020-01-01"}])]
    check = analysis(breaches=[{"name": "Acme", "date": "2024-09-09"}])
    assert any("2024-09-09" in issue for issue in verify.claims(check, results))


def test_unknown_subdomain_and_url_are_flagged():
    results = [
        result("crt_sh_subdomains", ["api.example.com"]),
        result("username_presence", {"found": [{"url": "https://github.com/other"}]}),
    ]
    check = analysis(
        subdomains=["api.example.com", "made-up.example.com"],
        associated_accounts=[{"platform": "GitHub", "url": "https://github.com/x"}],
    )
    issues = verify.claims(check, results)
    assert any("made-up" in issue for issue in issues)
    assert any("github.com/x" in issue for issue in issues)


def test_no_source_data_means_no_noise():
    assert verify.claims(analysis(breaches=[{"name": "Anything"}]), []) == []


def test_issue_list_is_capped():
    results = [result("breach_index", [])]
    check = analysis(breaches=[{"name": f"B{index}"} for index in range(20)])
    assert len(verify.claims(check, results)) == verify.MAX_ISSUES
