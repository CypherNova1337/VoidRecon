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
