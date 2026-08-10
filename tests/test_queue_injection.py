from voidrecon.core.queue import JobQueue
from voidrecon.modules.vuln.injection_probe import build_ssti_payloads, crlf_detected


def test_build_ssti_payloads():
    payloads, expect = build_ssti_payloads()
    assert expect.isdigit()
    assert any(expect in p or "*" in p for p in payloads)
    # The expected value is the product embedded in the payloads.
    assert len(payloads) >= 3


def test_crlf_detected():
    assert crlf_detected({"X-VoidRecon-Abc": "injected"}, "x-voidrecon-abc")
    assert not crlf_detected({"Server": "nginx"}, "x-voidrecon-abc")


def test_queue_add_claim_complete(tmp_path):
    q = JobQueue(tmp_path / "queue.db")
    n = q.add_many(["a.com", "b.com", "c.com"], {"active": True})
    assert n == 3
    assert q.stats().get("pending") == 3

    j1 = q.claim("worker-1")
    j2 = q.claim("worker-2")
    assert j1["target"] == "a.com" and j2["target"] == "b.com"  # FIFO
    assert j1["options"]["active"] is True
    assert q.stats().get("running") == 2

    q.complete(j1["id"], "done")
    q.complete(j2["id"], "failed", "boom")
    stats = q.stats()
    assert stats.get("done") == 1 and stats.get("failed") == 1 and stats.get("pending") == 1


def test_queue_claim_empty(tmp_path):
    q = JobQueue(tmp_path / "queue.db")
    assert q.claim("w") is None


def test_queue_no_double_claim(tmp_path):
    q = JobQueue(tmp_path / "queue.db")
    q.add("only.com")
    first = q.claim("w1")
    second = q.claim("w2")
    assert first is not None and second is None  # the single job is claimed once


def test_run_namespace_defaults():
    from voidrecon.cli import _run_namespace

    ns = _run_namespace(targets=["x.com"], aggressive=True)
    assert ns.targets == ["x.com"]
    assert ns.aggressive is True
    assert ns.no_live is True and ns.yes is True   # worker-safe defaults
    assert ns.resume is None


def test_read_targets_file_strips_scheme(tmp_path):
    from voidrecon.cli import _read_targets_file

    f = tmp_path / "targets.txt"
    f.write_text(
        "https://example.com\n"
        "http://app.example.com/login?next=/dashboard\n"
        "example.org\n"
        "HTTPS://Example.Com/          # dup after normalisation\n"
        "# a full-line comment\n"
        "sub.test.io:8443\n"
        "1.2.3.4\n"
        "  spaced.example.net  \n"
        "foo.com, bar.com\n"
    )
    got = _read_targets_file(str(f))
    # every entry is a bare host: scheme, path, query, port and case are stripped
    assert got == [
        "example.com",
        "app.example.com",
        "example.org",
        "sub.test.io",
        "1.2.3.4",
        "spaced.example.net",
        "foo.com",
        "bar.com",
    ]


def test_read_targets_file_missing(tmp_path):
    import pytest

    from voidrecon.cli import _read_targets_file

    with pytest.raises(FileNotFoundError):
        _read_targets_file(str(tmp_path / "nope.txt"))


def test_targets_file_feeds_scope(tmp_path):
    from voidrecon.cli import _build_scope, _run_namespace

    f = tmp_path / "t.txt"
    f.write_text("https://example.com/path\napp.example.org\n")
    ns = _run_namespace(targets=[], targets_file=str(f))
    scope = _build_scope(ns, wildcard_apex=True)
    assert "example.com" in scope.seeds
    assert scope.classify_host("app.example.org").value == "in_scope"
