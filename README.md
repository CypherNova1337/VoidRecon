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

> 🚧 **Work in progress.** VoidRecon is under active development and interfaces/defaults may change between releases. The engine and all core capabilities below are functional today.

VoidRecon maps a target's attack surface the way a real intruder does — **organisation-first, passive-before-active, and relentlessly focused on the forgotten corners** that cookie-cutter checklists skip. It is not "run three tools in a pipe." It is a full recon engine with a scope conscience, a scoring brain, a **live progress checklist**, resumable runs, a SQLite datastore with a web UI, and an extensible module system.

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
| **scope** | Org footprint: ASN + netblock mapping (shared-CDN ASNs recognised, not mis-claimed), RDAP registration intel (registrar/registrant/NS) | No (routing registries) |
| **passive** | Cert transparency, aggregated passive DNS (crt.sh, certspotter, OTX, anubis, urlscan, Censys, +key sources), web archives, GitHub dorking, search-engine dork generation, cloud-bucket discovery, DNS/email records (SPF/DMARC/DKIM/CAA), zone-transfer (AXFR) + SPF-chain mining, reverse-IP hosting lookup, breach correlation (HaveIBeenPwned), Shodan host enrichment | No (third-party data) |
| **resolve** | DNS resolution → live IPs + CNAME chains, wildcard-aware brute-force + altdns-style permutations, reverse-DNS (PTR) enrichment | No (recursive resolvers) |
| **active** | HTTP(S) probing/fingerprinting, high-value port discovery, live TLS-certificate SAN harvesting | **Yes** — gated |
| **content** | Native + SPA/XHR crawling, directory/file fuzzing (soft-404 aware), parameter discovery (reflected + accepted), virtual-host discovery, CSP/header host mining, deep tech fingerprinting, CMS enumeration (WordPress/Drupal/Joomla), JS secret/endpoint mining + source-map recovery, favicon-hash & tracking-ID pivoting (Shodan + Censys), API/spec discovery + deep GraphQL (introspection & suggestion harvesting), email harvesting, WAF/CDN detection, origin-IP discovery, HTTP method auditing, screenshotting | **Yes** — gated |
| **vuln** | Native version→CVE correlation (auto-refreshable), active subdomain-takeover verification, vuln-hint URL classification (SQLi/XSS/SSRF/LFI/RCE/redirect/SSTI/IDOR), open-redirect confirmation, JWT analysis (alg:none / no-expiry / authz claims), security-header / CORS / cookie analysis, template scanning, exposed-app flags | **Yes** — gated |
| **intel** | Scoring, correlation (host/favicon/tracker clusters, dangling records, dense netblocks), optional LLM analysis | No |

Re-run over time and use `voidrecon diff` to surface exactly what changed between runs — the moment a new subdomain, service, or finding appears.

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

# AGGRESSIVE — everything, maximum coverage. Prompts for confirmation first.
voidrecon run example.com --aggressive
voidrecon run example.com --aggressive --yes   # skip the prompt (automation)

# Import scope directly from a bug bounty program
voidrecon run --url https://hackerone.com/example --import-scope

# Compare the two most recent runs for a target (what changed?)
voidrecon diff example.com

# Build an HTML trend dashboard across all runs of a target
voidrecon dashboard example.com

# Refresh the local CVE signature dataset from an external feed
voidrecon update-cve https://example.com/voidrecon-cve.json

# Resume an interrupted run exactly where it stopped
voidrecon run example.com --resume example.com-20260809-184438

# Browse all runs, assets, and findings in a local web UI
voidrecon serve            # http://127.0.0.1:8787

# Inspect available modules / verify how a host classifies against your scope
voidrecon modules
voidrecon scope example.com --include "*.example.com" --check dev.example.com
```

Scope import uses the platform API when credentials are present (HackerOne:
`VOIDRECON_SOURCES_HACKERONE_USERNAME` + `VOIDRECON_SOURCES_HACKERONE_TOKEN`) and
falls back to best-effort parsing otherwise. It never probes the target and never
widens scope silently — it prints exactly what it imported.

While a run is in progress, VoidRecon shows a **live checklist** in the terminal — every planned module grouped by phase, each with a live status (pending / running / done / error), its elapsed time and assets added, plus running totals of the surface and findings. Disable it with `--no-live` (it's automatically off in pipes/CI). Detailed per-module logs still stream to `runs/<run>/voidrecon.log`.

Runs are **resumable**: after every module the datastore is checkpointed, so `--resume <run_id>` reloads it and continues from the next unfinished module — no lost hours if a scan is interrupted.

Output lands in `runs/<target>-<timestamp>/` as **JSON** (machine-readable), **Markdown** (operator report), and a self-contained **HTML** report with a prioritised target table and screenshot gallery. Every run is also appended to a shared SQLite database (`runs/voidrecon.db`) that powers `voidrecon diff`, `voidrecon dashboard`, and the `voidrecon serve` web UI.

### Aggressive mode

`--aggressive` (`-A`) is the "hit everything we can" switch. It:

- enables active mode and **every opt-in module** (HTTP probing, port scanning, crawling, JS mining, template scanning);
- widens the port sweep (top ~130 service ports) and deepens crawling;
- raises throughput (higher requests/sec and concurrency).

Because it is **loud and intrusive**, VoidRecon shows a warning and requires you to type `yes` before starting. In a non-interactive session (a pipe or CI) it refuses to run unless you pass `--yes`:

```bash
voidrecon run example.com --aggressive          # interactive confirmation
voidrecon run example.com --aggressive --yes    # confirmed up front (automation)
```

Even in aggressive mode the scope conscience still applies: **only positively in-scope, resolving assets are ever actively touched.** Use it only where you are explicitly authorized — it will be noticed and can trip rate limits, WAFs, and IDS/IPS.

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
export VOIDRECON_SOURCES_SHODAN_API_KEY=xxx            # favicon-hash pivoting
export VOIDRECON_SOURCES_CENSYS_API_ID=xxx             # extra passive subdomain source
export VOIDRECON_SOURCES_CENSYS_API_SECRET=xxx
export VOIDRECON_SOURCES_HACKERONE_USERNAME=xxx        # scope import (with token)
export VOIDRECON_SOURCES_HACKERONE_TOKEN=xxx
```

### Authenticated sessions

Reach behind a login so the crawler, fuzzer, API discovery, and analysis modules
test authenticated surface. Credentials attach to every active request (and the
SPA crawler replays headers in the browser):

```bash
voidrecon run app.example.com --active \
  --bearer "eyJhbGci..." \
  --header "X-Api-Key: abc123" \
  --cookie "session=deadbeef"
```

### Completion notifications

Point a Slack or Discord webhook at a long run and VoidRecon pings you when it
finishes, with the headline numbers and top findings (only if something at or
above `notify.min_severity` turned up):

```bash
voidrecon run example.com --aggressive --yes \
  --notify-webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
# or set VOIDRECON_NOTIFY_WEBHOOK in the environment
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
├── data/                  # bundled datasets (CVE signatures, subdomain wordlist)
└── utils/                 # domain/IP parsing, secret patterns, hashing, version compare
configs/default.yaml       # default configuration
tests/                     # pytest suite
```

## Screenshots & visual triage

The `screenshot` module (opt-in / aggressive) renders each live in-scope host with
headless Chromium and the HTML report builds a visual gallery, so you can triage
hundreds of hosts at a glance. Install the backend with `pip install -e ".[screenshots]"`
(then `playwright install chromium` if no browser is present). It honours
`HTTPS_PROXY`/`HTTP_PROXY` for use behind a corporate proxy.

## Roadmap

VoidRecon ships with the complete engine plus deep passive/OSINT, org
footprinting, DNS/email-security analysis, breach correlation, wildcard-aware
subdomain brute-force & permutations, reverse-DNS, active probing & port
discovery, native + SPA/XHR crawling, JS secret/endpoint mining, API/spec/GraphQL
discovery, email harvesting, favicon-hash & tracking-ID pivoting (Shodan +
Censys), WAF/CDN detection, cloud-bucket discovery, native CVE correlation with
an auto-refreshable dataset, security-header/CORS/cookie analysis, screenshotting,
SQLite persistence, run-to-run diffing, trend dashboards, and completion webhooks.
Still growing:

- Expanded/curated CVE + fingerprint datasets (bundled feeds)
- Authenticated login-flow automation (scripted form/OAuth login)
- Distributed multi-worker runs sharing one datastore
- Deeper injection-point testing (SSTI/CRLF/cache-deception candidates)

## Docker

The image bundles VoidRecon with the binaries it orchestrates (dns-helix,
paramvoid, subfinder, httpx, dnsx, katana, nuclei, gau) and a headless browser,
so the hybrid fast-path works out of the box:

```bash
docker build -t voidrecon .
docker run --rm -it -v "$PWD/runs:/runs" voidrecon run example.com
docker run --rm -it -v "$PWD/runs:/runs" voidrecon run example.com --aggressive --yes
```

Output is written to the mounted `/runs` volume. Pass API keys with `-e`, e.g.
`-e VOIDRECON_SOURCES_SHODAN_API_KEY=...`.

## Development

```bash
make setup    # editable install with dev + full extras (or: ./scripts/setup.sh)
make test     # pytest
make lint     # ruff
make run      # CLI help
```

CI (GitHub Actions) runs ruff + pytest on Python 3.10–3.12 for every push and PR.

## Integrations & credits

VoidRecon works standalone, but plays well with best-in-class tooling from the
VoidSec-Hub arsenal and the wider community — used automatically when present:

- **[dns-helix](https://github.com/CypherNova1337/dns-helix)** — its recommended
  resolver list is bundled and used for fast, reliable resolution/brute-force; the
  `dns-helix` binary is orchestrated when installed.
- **[paramvoid](https://github.com/CypherNova1337/paramvoid)** — its parameter
  wordlist ships with VoidRecon and the `paramvoid` binary is used for parameter
  discovery when installed.
- **[GF_Patterns](https://github.com/CypherNova1337/GF_Patterns)** — its
  vulnerability parameter sets power the `vuln_hints` URL classifier.
- ProjectDiscovery (`subfinder`, `httpx`, `naabu`, `nuclei`, `katana`), `gau`,
  `gospider`, `gowitness`, `amass` — orchestrated when on `PATH`.

Everything degrades gracefully when a tool or key is absent — nothing is required.

## Contributing

VoidRecon is a **VoidSec-Hub** project. Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Please keep the passive-by-default, scope-respecting philosophy intact: any module that touches a target must be `active = True` and gate on `ctx.can_touch(...)`.

## Legal & ethics

VoidRecon is a defensive-security and authorized-testing tool. Use it only against assets you own or are explicitly permitted to test under a bug bounty program or written engagement. The authors and VoidSec-Hub accept no liability for misuse. Verify every lead before acting on it, honour program scope, and comply with all applicable laws.

## License

[MIT](LICENSE) © 2026 VoidSec-Hub
