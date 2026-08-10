<div align="center">

```
 __     __    _     _ ____
 \ \   / /__ (_) __| |  _ \ ___  ___ ___  _ __
  \ \ / / _ \| |/ _` | |_) / _ \/ __/ _ \| '_ \
   \ V / (_) | | (_| |  _ <  __/ (_| (_) | | | |
    \_/ \___/|_|\__,_|_| \_\___|\___\___/|_| |_|
```

### Adversary-minded reconnaissance for authorized bug bounty & pentest engagements

**49 modules · 7 phases · Built-in AI Advisor**

*by [VoidSec-Hub](https://github.com/CypherNova1337)*

</div>

---

> 🚧 **Work in progress** — under active development; interfaces may shift between releases. The engine and everything below work today.

VoidRecon maps a target's attack surface the way a real intruder does — **organisation-first, passive-before-active, and focused on the forgotten corners** that checklists skip. It's not three tools in a pipe; it's a full recon engine with a scope conscience, a scoring brain, a built-in advisor that tells you what to do next, a live progress checklist, resumable and distributable runs, and reports you can actually use.

> ⚠️ **Authorized use only.** Passive collection is on by default. Anything that touches a target is gated behind `--active`/`--profile` **and** a positive in-scope check. Stay within your program's scope and the law.

---

## Quickstart

```bash
pip install -e .          # or: pip install -e ".[full]"  for every optional feature
voidrecon wizard          # interactive — asks a few questions, then runs
```

Prefer flags? Pick a one-word **profile**:

```bash
voidrecon run target.com --profile passive    # quiet OSINT only (safe default)
voidrecon run target.com --profile quick      # active, fast, essentials
voidrecon run target.com --profile standard   # active, default depth
voidrecon run target.com --profile deep       # active, every module
voidrecon run target.com --profile stealth    # active, very slow & quiet
```

Results land in `runs/<target>-<timestamp>/` as JSON, Markdown, and a self-contained HTML report — and every run is appended to `runs/voidrecon.db` for diffing, dashboards, and the web UI.

## Install

```bash
git clone https://github.com/CypherNova1337/VoidRecon && cd VoidRecon
pip install -e .              # core
pip install -e ".[full]"      # + tldextract, cryptography (TLS SANs), bs4
pip install -e ".[screenshots]"  # + Playwright (screenshots, SPA crawl, prototype-pollution)
```

Python 3.10+. Core deps: `httpx`, `PyYAML`, `rich`, `dnspython`. `voidrecon update` pulls the latest from `main`.

**Docker** (bundles the Go tools it orchestrates + a headless browser):

```bash
docker build -t voidrecon .
docker run --rm -it -v "$PWD/runs:/runs" voidrecon run target.com --profile deep
```

## Configure API keys (optional but recommended)

Run once — it saves your keys to `~/.config/voidrecon/config.yaml` and applies them to every run:

```bash
voidrecon setup
```

It walks you through GitHub, Shodan, Censys, SecurityTrails, VirusTotal, notification channels (Slack/Discord/**Telegram**), the optional LLM, and an OOB domain for blind SSRF. Everything is optional — VoidRecon degrades gracefully without any key. You can also use environment variables (`VOIDRECON_SOURCES_*`, `VOIDRECON_NOTIFY_*`).

## How it works

VoidRecon runs as ordered **phases**, each enriching one shared, de-duplicated datastore. A dead source never aborts the run.

| Phase | What happens | Touches target? |
|-------|--------------|:---------------:|
| **scope** | ASN + netblock footprint (shared-CDN aware), RDAP registration intel | No |
| **passive** | Cert transparency, 8+ passive-DNS sources, web archives, GitHub dorking, dork generation, cloud buckets, DNS/email (SPF/DMARC/DKIM/CAA), AXFR + SPF-chain mining, reverse-IP, breaches, Shodan enrichment | No |
| **resolve** | DNS resolution, wildcard-aware brute-force + permutations, reverse-DNS | No |
| **active** | HTTP probing/fingerprinting, port discovery, live TLS-SAN harvesting | **Yes** |
| **content** | Native + SPA crawling, dir/file fuzzing, parameter discovery, vhosts, CSP mining, deep tech fingerprint, CMS enum, JS mining + source maps, favicon/tracker pivoting, API + GraphQL, email harvesting, WAF detection, origin-IP unmasking, screenshots | **Yes** |
| **vuln** | CVE correlation, subdomain-takeover verification, SQLi/SSRF/SSTI/CRLF/XSS/prototype-pollution/cache-deception/open-redirect probing, vuln-hint URL classification, JWT analysis, header/CORS/cookie analysis | **Yes** |
| **intel** | Scoring, correlation, **the Advisor**, optional LLM analysis | No |

See everything with `voidrecon modules`.

## Intelligence & AI

VoidRecon's "brain" works with **no API key and no limits** — the AI value doesn't depend on a paid LLM plan:

- **Scoring** ranks every asset by juiciness (dev/admin/API/exposed signals, risky ports, dangling records, secrets).
- **The Advisor** reads the whole run and writes a plain-English **analyst summary** plus a ranked **next-step plan** — each step naming the assets and a ready-to-run command. It prints at the end of every run and headlines the report.
- **Optional LLM** (`--ai`) augments the plan when you have a key (OpenAI / Anthropic / local Ollama). Purely additive — everything above works without it.

```bash
voidrecon run target.com --profile standard --ai         # uses configured LLM if present
voidrecon run target.com --ai --llm-provider ollama --llm-model llama3.1   # fully local
```

## Notifications

Get pinged when a long run finishes (only if something at/above `notify.min_severity` turns up):

```bash
voidrecon run target.com --profile deep --notify-webhook https://hooks.slack.com/...   # Slack/Discord
# Telegram (set once via `voidrecon setup`, or):
export VOIDRECON_NOTIFY_TELEGRAM_TOKEN=123:abc VOIDRECON_NOTIFY_TELEGRAM_CHAT_ID=456789
```

## Output & review

Each run folder (`runs/<target>-<timestamp>/`) contains the JSON/Markdown/HTML report **plus ready-to-use candidate lists** — one file per vulnerability class, so you can feed a whole class straight into the right tool.

The lists are **deduplicated by injection point**, not by URL. A vulnerability lives at a parameter on a path, not at a specific value — so `/flows?id=1`, `/flows?id=2` … `/flows?id=999` collapse to **one** target (the `id` parameter on `/flows`), while `/flows?sort=name` stays separate because it's a different parameter. Each line keeps a real, non-empty value so dalfox/sqlmap/nuclei don't choke. That turns a 50-line dump of the same endpoint into the handful of distinct tests you actually need to run:

```
runs/<target>-<timestamp>/
├── report.html / report.md / voidrecon.json
├── dorks-<target>.html          # clickable Google/GitHub/Shodan dorks
└── candidates/
    ├── sqli.txt   xss.txt   ssrf.txt   lfi.txt   rce.txt
    ├── redirect.txt  ssti.txt  idor.txt  ...
```

```bash
# Pipe a whole class into the right tool — no copy/paste
sqlmap -m runs/target.com-*/candidates/sqli.txt --batch
cat runs/target.com-*/candidates/xss.txt   | dalfox pipe
cat runs/target.com-*/candidates/lfi.txt   | nuclei -t lfi/
cat runs/target.com-*/candidates/redirect.txt | while read u; do echo "$u"; done
```

And to browse/track results:

```bash
voidrecon serve                 # web UI over the datastore (runs, findings, filter, search)
voidrecon dashboard target.com  # HTML trend dashboard across runs
voidrecon diff target.com       # what changed since last run (new/removed assets & findings)
```

## Advanced

```bash
# Authenticated recon — logs in with a browser, reuses the session everywhere
voidrecon run app.target.com --profile deep \
  --login-url https://app.target.com/login --login-user u --login-pass p

# Distributed — many workers drain one queue into one datastore
voidrecon queue add a.com b.com c.com --active
voidrecon worker &  voidrecon worker &

# Resume an interrupted run exactly where it stopped
voidrecon run target.com --resume target.com-20260810-101500

# Everything, loudest (confirmation required)
voidrecon run target.com --aggressive
```

## Commands

| Command | Purpose |
|---------|---------|
| `run` | Run a reconnaissance engagement |
| `wizard` | Interactive guided setup + run |
| `setup` | Configure API keys & notifications |
| `modules` | List all modules |
| `scope` | Parse/verify scope without running |
| `diff` | Compare two runs |
| `dashboard` | Build an HTML trend dashboard |
| `serve` | Web UI over the datastore |
| `queue` / `worker` | Distributed multi-worker runs |
| `update` | Check for / install a newer version |
| `update-cve` | Refresh the CVE signature dataset |

VoidRecon checks for a newer version at startup and prints a one-line notice if you're behind (never auto-updates; disable with `--no-update-check`).

## Configuration

Defaults live in [`configs/default.yaml`](configs/default.yaml). Precedence: built-in defaults → packaged config → `~/.config/voidrecon/config.yaml` (from `setup`) → `--config file` → env vars (`VOIDRECON_<SECTION>_<KEY>`) → CLI flags. Keys stay in the environment or your user config — never in the repo.

## Scope

```bash
voidrecon run target.com --include "*.target.com" --exclude blog.target.com
voidrecon run --scope-file program-scope.txt --url https://hackerone.com/x --import-scope
```

Scope entries accept apex domains (covering subdomains by default), explicit hosts, wildcards, IPs, CIDRs, and URLs. Out-of-scope assets are still *recorded* as leads but **never actively probed**.

## Integrations & credits

Used automatically when present; everything degrades gracefully without them:

- **[dns-helix](https://github.com/CypherNova1337/dns-helix)** — bundled resolver list; binary orchestrated for DNS brute-force.
- **[paramvoid](https://github.com/CypherNova1337/paramvoid)** — bundled parameter wordlist; binary used for parameter discovery.
- **[GF_Patterns](https://github.com/CypherNova1337/GF_Patterns)** — powers vuln-hint URL classification.
- ProjectDiscovery (`subfinder`, `httpx`, `naabu`, `nuclei`, `katana`), `gau`, `gowitness`, `amass`, `sourcemapper`.

## Development

```bash
make setup    # editable install with dev + full extras
make test     # pytest      (106 tests)
make lint     # ruff
```

CI runs ruff + pytest on Python 3.10–3.12. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CHANGELOG.md`](CHANGELOG.md).

## Legal & ethics

VoidRecon is for authorized security testing only — assets you own or are explicitly permitted to test under a bug bounty program or written engagement. Verify every lead before acting, honour program scope, and comply with all applicable laws. The authors and VoidSec-Hub accept no liability for misuse.

## License

[MIT](LICENSE) © 2026 VoidSec-Hub
