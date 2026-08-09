from voidrecon.core.history import diff_runs
from voidrecon.core.program import ImportedScope, _parse_json_scope, detect_platform


def test_detect_platform():
    assert detect_platform("https://hackerone.com/security") == ("hackerone", "security")
    assert detect_platform("https://bugcrowd.com/acme") == ("bugcrowd", "acme")
    assert detect_platform("https://example.com/scope.json")[0] == "generic"


def test_parse_json_scope_include_exclude():
    scope = ImportedScope()
    _parse_json_scope(scope, {"include": ["*.example.com"], "exclude": ["no.example.com"]})
    assert scope.include == ["*.example.com"]
    assert scope.exclude == ["no.example.com"]


def test_parse_json_scope_structured_scopes():
    scope = ImportedScope()
    data = {"data": [
        {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",
                        "eligible_for_submission": True}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "old.example.com",
                        "eligible_for_submission": False}},
        {"attributes": {"asset_type": "OTHER", "asset_identifier": "ignored",
                        "eligible_for_submission": True}},
    ]}
    _parse_json_scope(scope, data)
    assert "*.example.com" in scope.include
    assert "old.example.com" in scope.exclude
    assert "ignored" not in scope.include


def _run(assets, findings):
    return {"generated": "t", "store": {"assets": assets, "findings": findings}}


def test_diff_runs_detects_changes():
    old = _run(
        [{"kind": "subdomain", "value": "a.example.com", "score": 10}],
        [{"module": "m", "title": "old", "asset": "a.example.com", "severity": "low"}],
    )
    new = _run(
        [
            {"kind": "subdomain", "value": "a.example.com", "score": 40},   # score jump
            {"kind": "subdomain", "value": "b.example.com", "score": 20},   # new
        ],
        [{"module": "m", "title": "fresh", "asset": "b.example.com", "severity": "high"}],
    )
    diff = diff_runs(old, new)
    assert [a["value"] for a in diff.new_assets] == ["b.example.com"]
    assert [f["title"] for f in diff.new_findings] == ["fresh"]
    assert [f["title"] for f in diff.resolved_findings] == ["old"]
    assert diff.score_jumps and diff.score_jumps[0]["asset"] == "a.example.com"
    assert not diff.is_empty()
