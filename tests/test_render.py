import json

from osintkit import render
from osintkit.models import Analysis, CollectorResult, Report


def report():
    return Report(
        target="alice@example.com",
        target_type="email",
        model="test-model",
        elapsed_ms=12,
        collectors=[
            CollectorResult(collector="xposed_or_not", target="t", target_type="email", data={"found": 1}),
            CollectorResult(
                collector="hibp_breaches",
                target="t",
                target_type="email",
                ok=False,
                skipped=True,
                note="skipped: no key",
            ),
            CollectorResult(
                collector="code_mentions", target="t", target_type="email", ok=False, error="HTTP 500"
            ),
        ],
        analysis=Analysis(
            summary="A small footprint [with brackets].",
            breaches=[
                {"name": "Acme", "date": "2020-01-01", "data_types": ["Emails"], "source": "xposedornot"}
            ],
            associated_accounts=[{"platform": "GitHub", "handle": "alice", "url": "https://github.com/alice"}],
            infrastructure_notes=["No domain supplied."],
            subdomains=["api.example.com"],
            risk_level="high",
            recommendations=["Rotate the password."],
        ),
    )


def test_render_report_covers_every_section(console, text_of):
    render.render_report(report(), console)
    text = text_of()
    assert "A small footprint" in text
    assert "Acme" in text
    assert "Recommendations" in text
    assert "Source coverage" in text
    assert "HIGH" in text


def test_render_without_analysis(console, text_of):
    r = report()
    r.analysis = None
    render.render_report(r, console)
    assert "No analysis available" in text_of()


def test_markdown_contains_tables_and_gaps():
    md = render.to_markdown(report())
    assert "# OSINT report: alice@example.com" in md
    assert "| Acme | 2020-01-01 | Emails | xposedornot |" in md
    assert "`hibp_breaches`: skipped" in md
    assert "`code_mentions`: failed (HTTP 500)" in md
    assert md.endswith("\n")


def test_markdown_without_analysis():
    r = report()
    r.analysis = None
    md = render.to_markdown(r)
    assert "No analysis available" in md


def test_risk_bar_marks_reached_levels():
    text = render.bar("high")
    assert "HIGH" in text.plain
    assert text.plain.count("▇") == 3


def test_print_json_roundtrips(capsys):
    render.print_json(report())
    payload = json.loads(capsys.readouterr().out)
    assert payload["analysis"]["risk_level"] == "high"
    assert payload["target"] == "alice@example.com"


def test_verbose_shows_raw_data(console, text_of):
    render.render_report(report(), console, verbose=True)
    text = text_of()
    assert "Raw source data" in text
    assert "xposed_or_not" in text


def test_notes_are_rendered(console, text_of):
    r = report()
    r.analysis = None
    r.notes.append("synthesis failed: boom")
    render.render_report(r, console)
    assert "synthesis failed: boom" in text_of()


def test_notes_in_markdown_without_analysis():
    r = report()
    r.analysis = None
    r.notes.append("synthesis failed: boom")
    assert "synthesis failed: boom" in render.to_markdown(r)
