<div align="center">

```
 __     __    _     _ ____
 \ \   / /__ (_) __| |  _ \ ___  ___ ___  _ __
  \ \ / / _ \| |/ _` | |_) / _ \/ __/ _ \| '_ \
   \ V / (_) | | (_| |  _ <  __/ (_| (_) | | | |
    \_/ \___/|_|\__,_|_| \_\___|\___\___/|_| |_|
```

### Adversary-minded reconnaissance for authorized bug bounty & pentest engagements

**49 modules · 7 phases · Built-in AI Analyst (keyless)**

*by [VoidSec-Hub](https://github.com/CypherNova1337)*

</div>

---

> 🚧 **Work in progress** — under active development; interfaces may shift between releases. The engine and everything below work today.

VoidRecon maps a target's attack surface the way a real intruder does — **organisation-first, passive-before-active, and focused on the forgotten corners** that checklists skip. It's not three tools in a pipe; it's a full recon engine with a scope conscience, a scoring brain, a built-in Analyst that reasons out your next move, a live progress checklist, resumable and distributable runs, and reports you can actually use.

> ⚠️ **Authorized use only.** Passive collection is on by default. Anything that touches a target is gated behind `--active`/`--profile` **and** a positive in-scope check. Stay within your program's scope and the law.

---

## Quickstart

```bash
pip install -e .          # or: pip install -e ".[full]"  for every optional feature
voidrecon wizard          # interactive — asks a few questions, then runs
```

The wizard takes either domains typed inline **or a path to a list file** — any
text file with one target per line. Prefixes and paths are stripped
automatically, so a list exported as `https://example.com/login` runs exactly
like a bare `example.com`.

Prefer flags? Pick a one-word **profile**:

```bash
voidrecon run target.com --profile passive    # quiet OSINT only (safe default)
voidrecon run target.com --profile quick      # active, fast, essentials
voidrecon run target.com --profile standard   # active, default depth
voidrecon run target.com --profile deep       # active, every module
voidrecon run target.com --profile stealth    # active, very slow & quiet

voidrecon run --targets-file targets.txt --profile deep   # feed a whole list at once
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
| **intel** | Finding-aware scoring, correlation, **the Analyst** (attack chains + dossiers), optional LLM | No |

See everything with `voidrecon modules`.

## Intelligence & AI

VoidRecon's "brain" works with **no API key and no limits** — the AI value doesn't depend on a paid LLM plan:

- **Finding-aware scoring** ranks every asset by juiciness (dev/admin/API/exposed signals, risky ports, dangling records, secrets) *and folds in the findings actually landed on it* — a host with a real HIGH bug outranks one that merely looks juicy by name.
- **The Analyst** reasons per host, not over a flat list. For each promising target it fuses the host's signals with its findings, recognises **multi-signal attack chains** that only make sense when several things co-occur on the *same* host, and writes a grounded **dossier** — what the host is, why it matters, and the exact play to run next:

  ```
  Attack plan — highest-value plays:
    1. Leaked credential → authenticated access  on admin-api.target.com  (impact 92)
       A secret leaks on a host that also gates access. Validate the secret
       against the login/API — a live key walks you straight past the gate.
    2. SQLi on a privileged surface  on admin-api.target.com  (impact 86)
       → sqlmap -u 'https://admin-api.target.com/flows?id=1' --batch --risk 2 --level 3
  ```

  A chain fires only on real co-occurrence — a secret on one host and a login gate on another won't invent a play. The plan prints at the end of every run and renders as **Attack plan** / **Target dossiers** in the report.
- **Optional LLM** (`--ai`) is *seeded with the Analyst's chains and dossiers* and asked to sharpen them (OpenAI / Anthropic / local Ollama) — it refines real reasoning instead of starting from scratch. Purely additive; everything above works without it.

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

## Recon coverage — you can see what actually ran

Passive OSINT sources fail in ways that used to be invisible: a rate-limit, a
block, or a timeout looked identical to "nothing there," so a section coming back
empty told you nothing. Every run now ends with a **Recon coverage** panel (in the
terminal and in the report) showing exactly what each source returned:

```
Recon coverage:
  ✓ crt.sh           ok (63)
  ✓ certspotter      ok (12)
  ✗ hackertarget     RATE-LIMITED
  ✗ urlscan          BLOCKED (403/401)
  • securitytrails   needs API key
  • otx              nothing found

  ⚠ 2 source(s) failed (rate-limited/blocked/timed out): hackertarget, urlscan.
    An empty section may be a failed source, not an empty target —
    add API keys (voidrecon setup) or re-run to fill gaps.
```

Rate-limited sources (HTTP 429) are retried honouring `Retry-After` instead of
being dropped, and the slow-but-rich sources (crt.sh, the Wayback index) get a
longer timeout and a retry so they stop silently falling out. `otx: nothing found`
is a real empty; `hackertarget: RATE-LIMITED` is a gap you can close.

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
