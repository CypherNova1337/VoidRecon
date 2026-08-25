"""Hardening from a hunter's field triage: kill secret/bucket false positives,
Cloudflare Access enumeration, wayback delta, LLM status visibility."""

from __future__ import annotations

import base64
import json

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Severity
from voidrecon.core.scope import Scope
from voidrecon.intel import correlate
from voidrecon.utils.text import find_secrets, looks_like_real_secret, shannon_entropy


# ---- secret detection -----------------------------------------------------
def test_placeholders_are_not_secrets():
    for fp in ('api_key = "your_api_key_here"', 'apikey: "YOUR_API_KEY"',
               'secret = "changeme"', 'token = "xxxxxxxxxxxxxxxx"',
               'password = "example_password"', 'api_key: "INSERT_KEY_HERE"',
               'client_secret = "<your-secret>"', 'access_key = "aaaaaaaaaaaa"'):
        assert find_secrets(fp) == [], fp


def test_real_secrets_still_detected():
    # Build secret-shaped tokens at runtime so no literal vendor secret sits in
    # source (that would trip secret-scanning push protection) while still
    # exercising the detector on the full shape.
    high_entropy = "a8Fk92Lm4Qz7Xr1Vt6Yw3Bn5Cp0Dh"
    gh_pat = "ghp_" + ("A1b2C3d4E5f6G7h8" * 2) + "I9j0"          # ghp_ + 36 chars
    stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dcXY"      # sk_live_ + 26 chars
    assert find_secrets(f'token = "{high_entropy}"')
    assert find_secrets(gh_pat)
    assert find_secrets(f'key = "{stripe}"')


def test_entropy_and_screen_helpers():
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("a8Fk92Lm4Qz7Xr1Vt6Yw3Bn5Cp0Dh") > 3.5
    assert looks_like_real_secret("a8Fk92Lm4Qz7Xr1Vt6Yw3Bn5Cp0Dh")
    assert not looks_like_real_secret("your_api_key_here")
    assert not looks_like_real_secret("abc1.apps.googleusercontent.com")  # public client id


# ---- cloud bucket provenance ----------------------------------------------
def _ctx():
    return RunContext(Config.load(), Scope.from_lists(["example.com"]))


def test_squatter_bucket_stays_unverified():
    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.CLOUD_RESOURCE, "https://example-backup.s3.amazonaws.com/",
                              tags={"cloud", "public", "unverified-owner"},
                              attrs={"bucket": "example-backup", "provider": "AWS S3"}))
    # no subdomain points at it -> ownership stays unverified, no HIGH upgrade
    correlate._verify_bucket_ownership(ctx)
    owned = [f for f in ctx.store.findings() if "Confirmed target-owned" in f.title]
    assert owned == []
    b = ctx.store.get_asset(AssetKind.CLOUD_RESOURCE, "https://example-backup.s3.amazonaws.com/")
    assert "unverified-owner" in b.tags and "owned" not in b.tags


def test_bucket_with_cname_provenance_is_upgraded():
    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.CLOUD_RESOURCE, "https://example-assets.s3.amazonaws.com/",
                              tags={"cloud", "public", "unverified-owner"},
                              attrs={"bucket": "example-assets", "provider": "AWS S3"}))
    # a real target host CNAMEs onto the bucket -> proof of ownership
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "assets.example.com",
                              attrs={"cname": "example-assets.s3.amazonaws.com"}))
    correlate._verify_bucket_ownership(ctx)
    owned = [f for f in ctx.store.findings() if "Confirmed target-owned" in f.title]
    assert len(owned) == 1 and owned[0].severity == Severity.HIGH
    b = ctx.store.get_asset(AssetKind.CLOUD_RESOURCE, "https://example-assets.s3.amazonaws.com/")
    assert "owned" in b.tags and "unverified-owner" not in b.tags
    assert b.attrs["provenance_host"] == "assets.example.com"


# ---- cloudflare access ----------------------------------------------------
def test_cf_access_decodes_meta_and_groups(monkeypatch):
    from voidrecon.modules.content import cf_access

    # a CF Access 'meta' blob is a base64url JWT-ish payload — no secret to decode
    payload = base64.urlsafe_b64encode(json.dumps({"aud": "APP-AUD-123"}).encode()).decode().rstrip("=")
    meta = f"eyJhbGciOiJub25lIn0.{payload}."
    location = (f"https://acmeteam.cloudflareaccess.com/cdn-cgi/access/login/"
                f"app.example.com?kid=KEY123&meta={meta}")

    decoded = cf_access._b64url_json(meta)
    assert decoded == {"aud": "APP-AUD-123"}
    assert cf_access._LOGIN_RE.search(location)

    ctx = RunContext(Config.load(overrides={"opsec": {"allow_active": True}}),
                     Scope.from_lists(["example.com"]))
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "app.example.com",
                              tags={"web"}, attrs={"http_status": 302}))
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "portal.example.com",
                              tags={"web"}, attrs={"http_status": 302}))

    class _Resp:
        def __init__(self, loc):
            self.status_code = 302
            self.headers = {"location": loc}
            self.text = ""

    async def fake_get(url, **kw):
        host = url.split("://", 1)[1].split("/", 1)[0]
        return _Resp(location.replace("app.example.com", host))

    monkeypatch.setattr(ctx.http, "get", fake_get)
    mod = cf_access.CloudflareAccess()
    import asyncio
    asyncio.run(mod.run(ctx))

    groups = [f for f in ctx.store.findings() if "Access policy group" in f.title]
    assert groups, "expected a policy group finding"
    ev = groups[0].evidence
    assert ev["kid"] == "KEY123"
    assert set(ev["hosts"]) == {"app.example.com", "portal.example.com"}  # grouped by shared kid


# ---- wayback delta --------------------------------------------------------
def test_wayback_flags_new_endpoints(tmp_path):
    from voidrecon.modules.passive.wayback import Wayback

    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    prior = {"https://example.com/old?id=1"}
    urls = {"https://example.com/old?id=1", "https://example.com/new?token=2"}
    Wayback()._ingest(ctx, "example.com", urls, prior)
    deltas = [f for f in ctx.store.findings() if "new archived endpoint" in f.title]
    assert len(deltas) == 1
    assert deltas[0].evidence["sample"] == ["https://example.com/new?token=2"]
    ep = ctx.store.get_asset(AssetKind.ENDPOINT, "https://example.com/new?token=2")
    assert "new-since-last" in ep.tags


# ---- llm status -----------------------------------------------------------
def test_llm_disabled_reason_is_explained():
    from voidrecon.intel.llm import LLMClient

    ctx = _ctx()  # llm not enabled by default
    assert "not enabled" in (LLMClient(ctx).disabled_reason() or "")
