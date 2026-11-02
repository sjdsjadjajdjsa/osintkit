from osintkit import offline
from osintkit.models import CollectorResult


def result(name, data, **kwargs):
    return CollectorResult(collector=name, target="example.com", target_type="domain", data=data, **kwargs)


def test_breaches_drive_risk_and_rotation():
    results = [
        result("breach_index", [{"name": "Acme", "data_types": ["Passwords"], "source": "x"}]),
        result("breach_index", []),
    ]
    analysis = offline.build(results, [], "a@b.co")
    assert analysis.risk_level == "medium"
    assert analysis.breaches[0].name == "Acme"
    assert "Rotate" in analysis.recommendations[0]


def test_missing_dmarc_is_recommended():
    results = [result("dns_mail_posture", {"spf_present": True, "spf_all": "-all", "dmarc_present": False})]
    analysis = offline.build(results, [], "example.com")
    assert any("DMARC" in note for note in analysis.infrastructure_notes)
    assert any("DMARC" in rec for rec in analysis.recommendations)


def test_loose_spf_is_recommended():
    results = [
        result(
            "dns_mail_posture",
            {"spf_present": True, "spf_all": "~all", "dmarc_present": True, "dmarc_policy": "reject"},
        )
    ]
    analysis = offline.build(results, [], "example.com")
    assert any("-all" in rec for rec in analysis.recommendations)


def test_risky_port_raises_risk_and_is_noted():
    results = [result("tcp_ports", {"open": [{"port": 6379, "service": "redis"}]})]
    analysis = offline.build(results, [], "example.com")
    assert analysis.risk_level == "medium"
    assert any("6379" in note for note in analysis.infrastructure_notes)
    assert any("firewall" in rec for rec in analysis.recommendations)


def test_accounts_come_from_presence_and_profile():
    results = [
        result(
            "username_presence",
            {"handle": "alice", "found": [{"site": "GitHub", "url": "https://github.com/alice"}]},
        ),
        result("github_profile", {"profile": {"login": "alice", "url": "https://github.com/alice"}}),
    ]
    analysis = offline.build(results, [], "alice")
    assert [account.platform for account in analysis.associated_accounts] == ["GitHub", "GitHub"]
    assert "unconfirmed" in analysis.associated_accounts[0].note


def test_subdomains_are_deduped_and_capped():
    hosts = [{"host": f"h{index}.example.com"} for index in range(40)]
    results = [
        result("passive_subdomains", {"live_hosts": hosts}),
        result("crt_sh_subdomains", ["h0.example.com"]),
    ]
    analysis = offline.build(results, [], "example.com")
    assert len(analysis.subdomains) == offline.MAX_SUBDOMAINS
    assert analysis.subdomains[0] == "h0.example.com"


def test_wildcard_without_dmarc_is_medium():
    results = [
        result("dns_wildcard", {"wildcard": True}),
        result(
            "dns_mail_posture",
            {"dmarc_present": True, "spf_present": True, "spf_all": "-all", "dmarc_policy": "reject"},
        ),
    ]
    analysis = offline.build(results, [], "example.com")
    assert any("Wildcard" in note for note in analysis.infrastructure_notes)
    assert any("wildcard" in rec for rec in analysis.recommendations)


def test_gaps_are_reported_in_summary():
    results = [
        CollectorResult(collector="hibp_breaches", target="t", target_type="email", ok=False, skipped=True),
        CollectorResult(collector="dns_records", target="t", target_type="email", ok=False, error="boom"),
        result("dns_records", {"A": ["1.2.3.4"]}),
    ]
    analysis = offline.build(results, ["carried note"], "t")
    assert "Failed sources: dns_records" in analysis.summary
    assert "Skipped sources: hibp_breaches" in analysis.summary
    assert "carried note" in analysis.infrastructure_notes


def test_empty_collection_still_yields_a_report():
    analysis = offline.build([], [], "example.com")
    assert analysis.risk_level == "low"
    assert analysis.breaches == []
    assert analysis.recommendations


def test_narrated_summary_wording():
    analysis = offline.build([], [], "example.com", narrated=True)
    assert "model returned no summary" in analysis.summary
    assert "not narrated" not in analysis.summary
