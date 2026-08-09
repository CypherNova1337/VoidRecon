# Contributing to VoidRecon

VoidRecon is a **VoidSec-Hub** project. Thanks for helping build a recon engine
worth the record books. This guide keeps contributions consistent and, above all,
keeps the tool lawful and quiet by default.

## Ground rules

1. **Authorized-use posture is non-negotiable.** VoidRecon exists for bug bounty
   and sanctioned testing. Do not add features whose primary purpose is evasion,
   denial-of-service, mass untargeted scanning, or attacking assets without
   authorization.
2. **Passive by default.** A module that contacts the target directly *must* set
   `active = True` and *must* gate every outbound action on `ctx.can_touch(host)`
   (which is only true when active mode is on **and** the host is positively in
   scope). Passive modules query third-party data sources only.
3. **Never break the run.** A module that raises is caught by the pipeline, but
   prefer to fail soft: handle timeouts, missing keys, and empty responses
   gracefully. If an optional dependency or API key is absent, log a hint and
   return.
4. **No secrets in the repo.** API keys come from the environment
   (`VOIDRECON_SOURCES_*`). Never commit tokens, targets, or run output
   (`runs/` is gitignored).

## Writing a module

Drop a file anywhere under `voidrecon/modules/` — it is auto-discovered:

```python
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.models import AssetKind, Confidence

@register
class MySource(Module):
    name = "my_source"          # unique, snake_case
    phase = Phase.PASSIVE       # SCOPE | PASSIVE | RESOLVE | ACTIVE | CONTENT | VULN | INTEL
    active = False              # True if it touches the target
    description = "One-line summary shown in `voidrecon modules`"
    depends_on = ()             # names of modules that must run first

    async def run(self, ctx):
        data = await ctx.http.get_json("https://osint.example/api")
        for host in (data or {}).get("hosts", []):
            ctx.add_asset(AssetKind.SUBDOMAIN, host, source=self.name,
                          confidence=Confidence.LIKELY)
```

Guidelines:

- Emit results through `ctx.add_asset(...)` and `ctx.add_finding(...)` — they handle
  scope tagging, de-duplication, and enrichment merging.
- Use the shared `ctx.http` client so throttling and UA rotation apply.
- If a mature external binary does the job better, detect it with
  `ctx.tools.has("toolname")` and orchestrate it via `run_tool(...)`, but keep a
  native fallback so the module works without it.
- Score-relevant enrichment (open ports, http status/title, technologies,
  `takeover_candidate`, `secrets_found`) lands in `asset.attrs` and is picked up by
  the scoring engine automatically.

## Development setup

```bash
pip install -e ".[dev,full]"
pytest -q            # run the test suite
ruff check .         # lint
```

Please add tests for pure-logic changes (scope, scoring, parsing, config). Network
modules should degrade gracefully and don't need live-network tests.

## Commits & pull requests

- Write clear, imperative commit messages ("Add favicon-hash pivoting source").
- Keep PRs focused; one capability or fix per PR where practical.
- Describe *why* a source is reliable and *what* it costs (rate limits, keys).
- By contributing you agree your work is licensed under the project's
  [MIT License](LICENSE).

Questions or ideas? Open an issue. Happy hunting — responsibly.
