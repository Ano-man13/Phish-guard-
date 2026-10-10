import pytest

from app.services.findings import Finding
from app.services.risk_engine import assess, level_for


def f(category, weight, key=None):
    key = key or f"{category}_{weight}"
    return Finding(key=key, category=category, title=key, description="d", weight=weight)


def test_no_findings_is_low_zero():
    result = assess([])
    assert (result.score, result.level) == (0, "LOW")
    assert result.findings == []


@pytest.mark.parametrize("score,level", [
    (0, "LOW"), (29, "LOW"), (30, "MEDIUM"), (59, "MEDIUM"),
    (60, "HIGH"), (79, "HIGH"), (80, "CRITICAL"), (100, "CRITICAL"),
])
def test_level_boundaries(score, level):
    assert level_for(score) == level


def test_medium_from_single_category():
    result = assess([f("host", 25), f("host", 10)])
    assert (result.score, result.level) == (35, "MEDIUM")


def test_two_categories_add_combination_bonus_and_report_it():
    result = assess([f("transport", 15), f("host", 25)])
    assert result.combination_bonus == 10
    assert result.score == 50
    assert any(x.category == "combination" for x in result.findings)


def test_high_needs_two_categories():
    result = assess([f("transport", 30), f("host", 30)])
    assert result.level == "HIGH"


def test_critical_when_many_categories():
    result = assess([f("transport", 15), f("host", 25), f("structure", 15), f("impersonation", 20)])
    # 75 raw + 30 combination bonus = 105, capped at 100
    assert result.raw_total == 75
    assert result.combination_bonus == 30
    assert result.score == 100
    assert result.level == "CRITICAL"


def test_score_capped_at_100():
    findings = [f(c, 40) for c in ("transport", "host", "structure", "query", "impersonation")]
    assert assess(findings).score == 100


def test_single_category_cannot_be_high_or_critical():
    result = assess([f("host", 50), f("host", 50), f("host", 50)])
    assert result.score == 59
    assert result.level == "MEDIUM"
    assert result.cap_note


def test_keywords_alone_never_reach_medium():
    result = assess([f("keywords", 10, "a"), f("keywords", 10, "b"), f("keywords", 10, "c")])
    assert result.score == 29
    assert result.level == "LOW"
    assert result.cap_note


def test_single_keyword_is_small():
    result = assess([f("keywords", 10)])
    assert (result.score, result.level) == (10, "LOW")


def test_zero_weight_findings_ignored():
    assert assess([f("host", 0)]).score == 0


def test_finding_severity_labels():
    from app.services.findings import Finding, severity_for
    assert severity_for(25) == "HIGH"
    assert severity_for(15) == "MEDIUM"
    assert severity_for(5) == "LOW"
    assert Finding(key="k", category="c", title="t", description="d", weight=20).severity == "HIGH"
    assert Finding(key="k", category="c", title="t", description="d", weight=10).severity == "MEDIUM"
    assert Finding(key="k", category="c", title="t", description="d", weight=5).severity == "LOW"
