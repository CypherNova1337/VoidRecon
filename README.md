<div align="center">

```
 __     __    _     _ ____
 \ \   / /__ (_) __| |  _ \ ___  ___ ___  _ __
  \ \ / / _ \| |/ _` | |_) / _ \/ __/ _ \| '_ \
   \ V / (_) | | (_| |  _ <  __/ (_| (_) | | | |
    \_/ \___/|_|\__,_|_| \_\___|\___\___/|_| |_|
```

**Adversary-minded reconnaissance for authorized bug bounty & pentest engagements.**

*Maintained by [VoidSec-Hub](https://github.com/CypherNova1337)*

</div>

---

VoidRecon maps a target's attack surface the way a real intruder does — **organisation-first, passive-before-active, and relentlessly focused on the forgotten corners** that cookie-cutter checklists skip. It is not "run three tools in a pipe." It is a full recon engine with a scope conscience, a scoring brain, and an extensible module system.

> ⚠️ **Authorized use only.** VoidRecon is built for bug bounty programs and sanctioned penetration tests. Passive collection is on by default; anything that *touches the target* is gated behind an explicit `--active` flag **and** a positive in-scope check. You are responsible for staying within your authorization and the law.

## Why VoidRecon is different

Most guides teach the same shallow loop: `subfinder | httpx | nuclei`. An attacker doesn't think in tools — they think in **footprint, opportunity, and the path of least resistance**. VoidRecon encodes that mindset:

- **Organisation-first footprinting.** From a single seed domain it maps the org's ASNs and announced IP ranges (via public routing registries), because the real surface is rarely one domain.
- **Passive by default, quiet by design.** Every source queried in the default run talks to *third-party datasets*, never the target. Rate limiting, jitter, and user-agent rotation are built in for when you do go active.
- **A scope engine that is also a conscience.** Out-of-scope assets are still *discovered and recorded* (they're leads — acquisitions, siblings, third parties) but are tagged and **never actively probed**. Only positively in-scope, resolving hosts are ever touched.
- **A scoring brain.** Hundreds of assets are meaningless without prioritisation. VoidRecon scores every asset for "juiciness" — dev/staging/admin/API surfaces, exposed infra, dangling records, secrets — so your eye lands on the right target first. This works with zero API keys, fully offline.
- **Optional intelligence layer.** Plug in any LLM (OpenAI, Anthropic, Ollama, or an OpenAI-compatible gateway) to have a model reason over the highest-priority surface and nominate attack paths. Entirely optional — the tool is fully functional without it.
- **Hybrid tooling.** Native logic for everything essential, but if best-in-class binaries are installed (`subfinder`, `httpx`, `naabu`, `nuclei`, `katana`, `gau`…) VoidRecon orchestrates them automatically and merges their output. Nothing breaks if they're absent.

## The recon workflow

VoidRecon runs as ordered **phases**, each populating a shared, de-duplicated datastore:

| Phase | What happens | Touches target? |
|-------|--------------|-----------------|
| **scope** | Org footprint: ASN + netblock mapping from seed domains | No (routing registries) |
| **passive** | Cert transparency, aggregated passive DNS, web archives, GitHub dorking | No (third-party data) |
| **resolve** | DNS resolution → live IPs + CNAME chains (feeds takeover detection) | No (recursive resolvers) |
| **active** | HTTP(S) probing/fingerprinting, high-value port discovery | **Yes** — gated |
| **content** | JavaScript secret/endpoint mining, crawling | **Yes** — gated |
| **vuln** | Fingerprint→known-issue correlation, template scanning, exposed-app flags | **Yes** — gated |
| **intel** | Scoring, correlation (host clusters, dangling records, dense netblocks), optional LLM analysis | No |

A single dead source never aborts a run — the error is logged and the engagement continues, exactly how an operator works.

## Install

```bash
git clone https://github.com/CypherNova1337/VoidRecon
cd VoidRecon
pip install -e .            # core install
pip install -e ".[full]"    # + optional accelerators (tldextract, mmh3, bs4)
```

Requires Python 3.10+. Core dependencies: `httpx`, `PyYAML`, `rich`, `dnspython`.

## Quickstart

```bash
# Quiet, passive-only recon (the default)
voidrecon run example.com

# Explicit scope with an out-of-scope exclusion
voidrecon run example.com --include "*.example.com" --exclude blog.example.com

# Load scope from a program's policy (txt lines, or JSON/YAML with include/exclude)
voidrecon run --scope-file program-scope.txt --url https://hackerone.com/example

# Go active — only touches positively in-scope, resolving hosts
voidrecon run example.com --active

# Add opt-in noisy modules once you're authorized
voidrecon run example.com --active --only http_probe,port_scan,tech_cve

# Inspect available modules / verify how a host classifies against your scope
voidrecon modules
voidrecon scope example.com --include "*.example.com" --check dev.example.com
```

Output lands in `runs/<target>-<timestamp>/` as **JSON** (machine-readable), **Markdown** (operator report), and a self-contained **HTML** report with a prioritised target table.

### Scope files

A scope file can be plain text (one entry per line; prefix `!` for out-of-scope):

```
*.example.com
api.example.com
203.0.113.0/24
!internal.example.com
```

…or JSON/YAML:

```json
{ "include": ["*.example.com", "203.0.113.0/24"], "exclude": ["internal.example.com"] }
```

Scope entries accept apex domains (which cover subdomains by default), explicit hosts, wildcards, IPs, CIDR ranges, and URLs (the host is extracted).

## Configuration

Defaults live in [`configs/default.yaml`](configs/default.yaml). Override with `--config your.yaml`, individual CLI flags, or environment variables (`VOIDRECON_<SECTION>_<KEY>`). Key knobs:

```yaml
opsec:
  allow_active: false        # --active flips this on
  requests_per_second: 8.0
  jitter: 0.3
  rotate_user_agents: true
```

**API keys stay in the environment**, never in a file:

```bash
export VOIDRECON_SOURCES_GITHUB_TOKEN=ghp_xxx          # enables GitHub dorking
export VOIDRECON_SOURCES_SECURITYTRAILS_API_KEY=xxx    # enriches passive DNS
export VOIDRECON_SOURCES_VIRUSTOTAL_API_KEY=xxx
```

Everything works without any keys — configured sources simply add depth.

## The intelligence layer

The heuristic scorer is always on and offline. To add model-assisted analysis:

```bash
export VOIDRECON_LLM_API_KEY=sk-...
voidrecon run example.com --llm --llm-provider openai --llm-model gpt-4o-mini
# or, fully local:
voidrecon run example.com --llm --llm-provider ollama --llm-model llama3.1
```

The model receives a compact digest of the top-scoring assets and returns a summary, prioritised targets with suggested checks, thematic clusters, and anything the numeric scoring under-weighted. It is advisory only and **never triggers network actions on its own**.

## Extending VoidRecon

Adding a capability is intentionally tiny — drop a file anywhere under `voidrecon/modules/` and it's auto-discovered:

```python
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.models import AssetKind

@register
class MySource(Module):
    name = "my_source"
    phase = Phase.PASSIVE
    active = False
    description = "Where I found new hosts"

    async def run(self, ctx):
        data = await ctx.http.get_json("https://api.example-osint.com/x")
        for host in (data or {}).get("hosts", []):
            ctx.add_asset(AssetKind.SUBDOMAIN, host, source=self.name)
```

The context enforces scope tagging, throttling, and de-duplication for you. See the modules under `voidrecon/modules/passive/` for full-featured examples.

## Project layout

```
voidrecon/
├── cli.py                 # command-line interface
├── core/                  # engine: config, scope, models, store, http, pipeline, modules
├── intel/                 # scoring, correlation, provider-agnostic LLM layer
├── modules/               # auto-discovered recon modules (passive/active/content/vuln)
├── reporting/             # JSON / Markdown / HTML report generation
└── utils/                 # domain/IP parsing, secret patterns
configs/default.yaml       # default configuration
tests/                     # pytest suite
```

## Roadmap

VoidRecon ships today with the complete engine and a deep passive/OSINT layer, plus functional active probing and JS analysis. Actively growing:

- Native deep crawler (link/form/XHR endpoint & parameter mapping)
- Native CVE correlation against a local product/version dataset
- Favicon-hash and analytics-ID pivoting for cross-internet asset discovery
- Cloud-asset discovery (buckets, blobs, functions)
- Screenshotting and visual triage
- Historical diffing between runs

## Contributing

VoidRecon is a **VoidSec-Hub** project. Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Please keep the passive-by-default, scope-respecting philosophy intact: any module that touches a target must be `active = True` and gate on `ctx.can_touch(...)`.

## Legal & ethics

VoidRecon is a defensive-security and authorized-testing tool. Use it only against assets you own or are explicitly permitted to test under a bug bounty program or written engagement. The authors and VoidSec-Hub accept no liability for misuse. Verify every lead before acting on it, honour program scope, and comply with all applicable laws.

## License

[MIT](LICENSE) © 2026 VoidSec-Hub
