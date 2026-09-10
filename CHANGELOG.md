# Changelog

All notable changes to VoidRecon are documented here. Maintained by VoidSec-Hub.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
This project is pre-1.0 and under active development; interfaces may change.

## [Unreleased]

## [0.9.0] — Warrant

Client-ready milestone: after a run of external field reviews (see
`TOOL_FEEDBACK.md`), the pipeline no longer embarrasses itself on real
engagements. This release is the last two polish items.

### Improved
- **Tentative findings never lead the playbook.** A "Confirm and exploit …" step
  backed only by tentative evidence is demoted below every confirmed-signal step
  (and the review step), so the recommended next steps open on real signal.
- **Finding counts read as a story.** The report summary now breaks findings down
  by source (`blob_mining 4200, http_analysis 600, …`) in Markdown and as chips in
  HTML, so a large total shows where the volume comes from instead of scaring the
  reader with one number.

## [0.8.3]

### Fixed — "Where to test" points at in-scope surface
- The finding attribution was correct, but the **"Where to test" URL could still
  show a host the crawler merely followed a redirect to** (e.g. a Google OAuth URL
  on a "missing security headers" finding for an in-scope host). Now the report
  drops evidence URLs whose host is outside the engagement and falls back to the
  finding's own in-scope asset URL — so the pointer always aims at the target's
  surface. External-leak findings whose off-domain URL *is* the point (GitHub
  hits, subdomain-takeover, OAuth-flow intel, cloud buckets, breaches, scope
  expansion) keep their URL.

## [0.8.2]

### Fixed — OAuth/OIDC handling + open-redirect over-filtering (v0.8.1 re-review)
- **OIDC discovery is not an "exposed spec".** A ``/.well-known/openid-configuration``
  is public by design; it was being reported as an "Exposed API specification"
  pointing at the identity provider (accounts.google.com). It's now an INFO
  **OAuth/OIDC** signal attributed to the in-scope host, recording the issuer and
  authorize/token endpoints as recon — not an exposure, not attributed to the IdP.
- **Harvested OAuth URLs become in-scope intel.** OAuth authorization/sign-in URLs
  the crawler picks up (e.g. ``accounts.google.com/o/oauth2/auth?client_id=…&
  redirect_uri=https://backstage.example.com/…``) are now mined for the target's
  client_id and the **in-scope redirect hosts** they trust, emitted as a LOW
  ``oauth-flow`` finding attributed to the in-scope host (and those redirect hosts
  recorded as assets) — surfacing real surface instead of a third-party finding.
- **Open-redirect / SSRF params no longer over-filtered.** 0.7.0's benign-param
  screen wrongly swept ``redirect_uri``/``next``/``return``/``url`` — the actual
  open-redirect & SSRF surface — into the excluded OAuth set, silently dropping
  those candidates. OAuth *token* params (``code``, ``state``, ``client_id``, …)
  stay excluded; the redirect/SSRF surface is classifiable again.
- **Resilience:** an optional native dep (``cryptography``) that fails to import
  with a low-level pyo3 panic no longer crashes module loading — the guard catches
  ``BaseException``, so the module simply skips as designed.

## [0.8.1]

### Fixed — third-party attribution leak (from the v0.8.0 re-review)
- **Findings stay inside the scope domain set.** The crawler could follow an OAuth
  redirect chain and attribute a third party's document to the target — e.g.
  `accounts.google.com/.well-known/openid-configuration` reported as an exposed
  Fivetran spec. Now:
  - `api_discovery` checks the **final** response URL after redirects; a spec/doc
    that resolves onto an off-domain host (`accounts.google.com`) is never emitted.
  - New `RunContext.is_target_host` / `is_target_url` define engagement membership
    (in scope, or under a seed apex; discovered IPs count).
  - `add_finding` labels any finding naming an off-domain host `third-party`
    (intentionally-external leads — scope expansion, provider CNAMEs — are left
    alone), and the Analyst excludes off-domain hosts from dossiers and plays.

## [0.8.0] — Sifter

### Fixed — SQLi false positives on static assets (from the v0.7.0 fivetran re-review)
The one embarrassing lead left after 0.7.0: boolean-based SQLi "candidates" on
Next.js ``/_next/data/*.json`` static files. Those have no database behind them —
the byte-count differences were SPA-rehydration noise, not injection.

- **Static-asset paths are never injection-probed.** New `utils.params.is_static_path`
  excludes framework data dirs (`/_next/`, `/_nuxt/`, `/static/`, `/assets/`, …) and
  static extensions (`.js`, `.css`, `.map`, `.json`, fonts, images, media) from
  `sqli_probe`, `injection_probe`, `open_redirect`, `ssrf_probe`, and the candidate
  classifier (`vuln_hints`) — so they never reach the candidate files either.
- **Boolean SQLi now requires a *reproducible* differential.** The endpoint's
  baseline must be deterministic across repeats (a wobbling SPA is skipped), each
  payload's response must be self-consistent across repeats, and only then does a
  true≈baseline / false-clearly-different pattern — comfortably above the measured
  noise floor — count. A one-off length diff is no longer SQLi.
- **Net effect:** with static-asset SQLi gone, real app-surface candidates (e.g. a
  `serviceId` parameter on an app route) rank at the top of the plan where they
  belong, instead of behind dead static-file leads.

## [0.7.0] — Calibre

### Severity calibration + false-positive gates (from the fivetran.com field review)
The tool was over-claiming: weak evidence read as HIGH and fed the attack plans.
This release makes evidence earn its severity.

- **Secrets require classification.** A structurally-valid vendor token
  (AKIA/AIza/ghp_/sk_live/JWT/private key) is HIGH; a generic `key="value"` match
  in a minified bundle is now INFO "high-entropy candidate" and **never seeds an
  attack play** (no `secrets_found`, no `secret` tag). Applied to JS mining, source
  maps, and GitHub dorking. Kills the empty-`secret_types`-but-HIGH class.
- **Non-200 on a sensitive path is not exposure.** `.git/HEAD → 403`, `.env → 401`
  are INFO "present but access-controlled" (the control working), not MEDIUM
  "exposed". A 200 that returns HTML on a non-HTML path is flagged as a likely SPA
  catch-all, not a leak. Only a 200 with real content is an exposure.
- **SQLi is differential.** Error-based detection now requires a DB-error string
  that appears **only after** injecting a quote (a data company's marketing page
  mentioning "PostgreSQL" no longer trips it), and analytics/OAuth params
  (`utm_*`, `code`, `state`, …) are never probed.
- **Spec detection requires a real spec.** `/swagger.json` etc. must return JSON
  (by content-type) that parses and carries spec markers; doc UIs must actually
  reference swagger/redoc — SPA catch-alls are no longer "exposed specs".
- **Candidate classifier gained URL-param semantics.** OAuth-return, analytics, and
  presentation params are excluded before bucketing, so OAuth `code`/`redirect_uri`
  stop becoming RCE/SSRF candidates and `utm_*` stops becoming SQLi. Candidate
  findings cap at LOW (they're leads).
- **Takeover distinguishes lead from confirmed.** A CNAME to a live provider is a
  *candidate* (INFO/MEDIUM), not a HIGH takeover; only `takeover_verify`'s
  unclaimed-resource fingerprint confirms one and seeds the takeover play. Dangling
  (non-resolving) vs live verdicts are now distinct and consistent.
- **The Analyst is scope- and status-aware.** Out-of-scope hosts never headline a
  play; non-prod (staging/dev/test) hosts carry a "confirm program scope" nudge;
  and because gated paths no longer carry `exposure`, a 401/403 can't seed a
  credential-recovery chain.
- **Next-steps respect the checkpoint.** Recommendations no longer tell you to run
  modules that already completed this session.
- **Report is navigable, not a dump.** Dossiers and the attack plan come first;
  findings are grouped and collapsed by severity (Critical/High open, the tail
  collapsed and capped) with the full set in `voidrecon.json`.

## [0.6.0] — Ledger

### Fixed / added (from a hunter's field triage)
- **Secret detection no longer cries wolf.** Placeholder values (`your_api_key`,
  `changeme`, `xxxx…`, `<your-secret>`, `example_password`) are blocked, the generic
  `key = "value"` match is entropy-scored on its value, and known-public identifiers
  (Google OAuth client IDs, …) are excluded. Structural tokens padded with `xxxx`
  are dropped too. This kills the 8-of-8 false-positive run — `find_secrets` is the
  shared chokepoint, so GitHub dorking, JS mining, and source-map analysis all get
  it. New `looks_like_real_secret()` / `shannon_entropy()` helpers.
- **Cloud buckets disambiguate ownership.** A bucket whose name merely matches the
  org is now flagged **MEDIUM, ownership-unverified** (name-squatting is common),
  not HIGH. `correlate` then runs a **provenance check** after DNS resolution: when
  a target host CNAMEs onto the bucket, it's upgraded to a **confirmed target-owned**
  HIGH exposure. Squatters stay unverified.
- **Cloudflare Access enumerator (new `cf_access` module).** For each live host it
  detects the Zero-Trust gate (`/cdn-cgi/access/…`), decodes the login redirect's
  public `kid` and base64 `meta` (no secrets involved), and **groups hosts by Access
  policy (kid) and team** — mapping which hosts share one gate and flagging the
  stray host under a different policy.
- **Wayback delta mode.** On a repeat scan, endpoints not seen in the previous run
  are tagged `new-since-last` and summarised as their own lead — the fresh surface
  to test first, instead of the same thousands of URLs every time.
- **Empty `llm_analysis` is explained.** The report now carries an `llm_status`
  ("not enabled — run with --ai…", "no API key in $…", "ok (provider/model)") so a
  blank LLM section is never a silent mystery; the keyless Analyst does the work
  regardless.

## [0.5.1]

### Fixed — no module can hang the run (from the Kraken field run)
- **Per-module time budget.** Every module now runs under a wall-clock budget
  (`opsec.module_timeout`, default 2h; per-module override `modules.<name>.timeout`;
  0 disables). If a module runs past it, it is cut off, recorded as a `timeout`, and
  the run continues — partial results kept. Previously a single runaway module could
  stall a run indefinitely (a large target left `origin_ip` running for days).
- **origin_ip bounded.** It now tests only the highest-scoring fronted hosts
  (`modules.origin_ip.max_hosts`, default 15) instead of the full host×IP
  cross-product, uses a short fail-fast per-probe timeout
  (`modules.origin_ip.probe_timeout`, default 6s) so dead IPs don't burn 20s each,
  and stops probing a host once its origin is found. On a large IP set this is the
  difference between minutes and days.

## [0.5.0] — Oracle

### The Analyst — the built-in AI is now a reasoning layer, not a template
- **Per-host reasoning.** A new always-on, keyless Analyst fuses each host's own
  signals (name tokens, HTTP posture, tech, exposure) with the findings actually
  landed on it, and writes a grounded **target dossier** — what the host is, why it
  matters, and the concrete next play. Reasoning happens per host, not over a flat
  global tag list.
- **Multi-signal attack chains.** It recognises plays that only make sense when
  several signals co-occur on the *same* host — e.g. *secret + auth-gate →
  "validate the leaked credential against the gate"*, *SQLi + admin → "SQLi on a
  privileged surface"* — and emits ready-to-run commands (real URL substituted).
  A chain does **not** fire when its signals are split across different hosts.
- **Finding-aware scoring.** Asset priority now folds in the findings on a host, so
  a host with a real HIGH finding outranks one that merely *looks* juicy by name —
  evidence beats hunches.
- **Findings are never dropped.** A host named only by a finding (no discovery
  module recorded it as an asset) is still reasoned about and can top the plan.
- **Surfaced everywhere.** The battle plan (highest-value plays + dossiers) prints
  in the terminal and renders as new **Attack plan** / **Target dossiers** sections
  in the Markdown and HTML reports.
- **LLM builds on it.** When the optional model is enabled it is now seeded with the
  Analyst's chains and dossiers and asked to sharpen them, instead of starting from
  a bare asset list.

## [0.4.0] — Specter

### Fixed / improved (recon visibility — the "sections come back zero" problem)
- **Passive sources no longer fail silently.** Previously a rate-limit (429), a
  block (403), a timeout, and a genuine "nothing there" all collapsed to the same
  empty result — so you could not tell a dead source from an empty target. Fetches
  are now *classified* (ok / empty / rate-limited / blocked / timed-out / needs-key)
  and each source records what it actually returned.
- **Rate limits are retried, not fatal.** HTTP 429 responses are honoured
  (`Retry-After` aware, exponential backoff), so a throttled source recovers
  within the run instead of contributing nothing. crt.sh and the Wayback CDX index
  get a longer timeout and a retry — the single richest keyless sources no longer
  drop out on a transient stall.
- **New "Recon coverage" panel.** Every run now prints a per-source health table
  (terminal + Markdown + HTML): what each source returned, with failed sources
  flagged and a banner warning that an empty section may be a failed source, not an
  empty target — with the fix (add API keys / re-run) called out.
- **More keyless subdomain sources.** Added RapidDNS and subdomain.center to the
  passive aggregator, so coverage no longer hinges on paid keys.

## [0.3.3]

### Added
- **Target list files.** The wizard now accepts a path to a text file (one target
  per line) in place of typed domains, and `voidrecon run` gained
  `--targets-file/-T`. Any `http://`/`https://` prefix, path, query, port and
  case are stripped to the bare host, so a list exported as
  `https://example.com/login` runs identically to `example.com`. Blank lines,
  `#` comments (whole-line or trailing), and comma/space-separated entries are
  tolerated; duplicates collapse in order.

## [0.3.2]

### Fixed / improved (from the Hytale field run)
- **Candidate lists are deduplicated by injection point, not by URL.** The same
  endpoint with different values — `/flows?id=1`, `/flows?id=2` … `/flows?id=999`
  — is one injection point (the `id` parameter on `/flows`) and now collapses to a
  single line; a different parameter on the same path (`/flows?sort=name`) stays a
  separate target. Each line keeps a non-empty parameter value so dalfox/sqlmap/
  nuclei don't error on empty inputs. A 50-line `idor.txt` of one endpoint becomes
  the handful of distinct tests you actually need to run.

### Fixed
- **`voidrecon update` stale-cache bug:** the updater re-fetches the latest version
  (bypassing the 24h cache) instead of reporting a cached "up to date" forever.
  Combined with 0.3.0's "always pull" fix, `voidrecon update` now reliably upgrades.

## [0.3.0] — Wraith

### Fixed / improved (from the Hytale field run)
- **No more double links:** references that duplicate the "Where to test" URLs are
  no longer rendered twice.
- **GitHub findings now say what was found:** they include the matched code snippet
  (via GitHub text-match), and screen it for real secrets — a live AWS/API key
  elevates to HIGH, plain config stays LOW.
- **No false ownership:** a community repo merely named ``<target>-*`` is labelled
  third-party; only a matching repo *owner* is called target-owned.
- **Cleaner titles / AI read:** long URLs in finding titles and the analyst read are
  collapsed to ``host/path?param=…`` so a giant token never floods the output.
- **README:** documents the per-class `candidates/*.txt` files with copy-paste
  sqlmap/dalfox/nuclei pipelines.

## [0.2.0] — Umbra

Everything since 0.1.0: 49 modules across all phases, the Advisor (keyless AI),
profiles/wizard, authenticated sessions, distributed workers, live progress,
resumable runs, SQLite + web UI + dashboard + diff, Docker, Telegram/Slack/Discord
notifications, and the integrations with dns-helix / paramvoid / GF_Patterns.
Highlights below.

### Fixed / improved (from live use)
- **Live display no longer freezes:** the progress table auto-refreshes, so the
  elapsed timer keeps moving during long modules (e.g. dns_brute).
- **Actionable findings:** each finding now lists "Where to test" (the exact
  URLs/params), and per-category **candidate files** are written to
  `runs/<run>/candidates/<class>.txt` (xss, lfi, sqli, …) for feeding other tools.
- **Clickable report:** HTML stat cards expand to the full asset list per kind;
  finding evidence renders as clickable links.
- **Better GitHub dorking:** skips forks and wordlist/dork/noise repos, dedupes
  per repo, aggregates hits, and ranks target-owned repos higher.
- **Clickable dork page:** `dork_report` writes `dorks-<apex>.html` with
  ready-to-click Google/GitHub/infra queries.
- **Deeper AI read:** the Advisor's analyst summary is now multi-part (surface,
  severity breakdown, named urgent findings, prioritised hosts, attack paths).

### Added (setup, Telegram, keyless AI, version check)
- **`voidrecon setup`:** interactive configuration of API keys and notifications,
  saved to `~/.config/voidrecon/config.yaml` (now auto-loaded on every run).
- **Telegram notifications:** alongside Slack/Discord (bot token + chat id).
- **Keyless AI:** the Advisor now writes a natural-language "analyst read" and
  attack-path chaining — real intelligence with no LLM key and no API limits; the
  optional LLM only augments it.
- **Version check:** startup notice when a newer version exists (cached, best-effort,
  `--no-update-check` to disable) plus a `voidrecon update` command (git/pip).

### Added (usability, the Advisor, injection refinements)
- **The Advisor:** an always-on, heuristic "what to do next" planner — ranks
  findings into concrete next steps with the assets involved and ready-to-run
  commands; prints after every run and headlines the JSON/Markdown/HTML report.
- **Profiles:** `--profile passive|quick|standard|deep|stealth` — one word instead
  of a pile of flags.
- **Interactive wizard:** `voidrecon wizard` guides target/intensity/AI choices.
- **`--ai` flag:** turns on LLM analysis with env/config provider settings.
- **sqli_probe:** error-based + boolean-based SQL-injection confirmation.
- **ssrf_probe:** blind SSRF via OOB callbacks (`oob.domain`) + in-band signals.
- **prototype_pollution:** real-browser client-side prototype-pollution detection.
- **Web UI:** global `/findings` view with severity filter and search.

### Added (auth automation, distributed workers, injection probing)
- **Authenticated login automation:** scripted headless-browser login
  (`--login-url/--login-user/--login-pass` or `auth.login`) captures the session
  and feeds it to every active module; handles many OAuth-backed logins.
- **Distributed runs:** SQLite-backed work queue with atomic claiming — new
  `voidrecon queue add|list|clear` and `voidrecon worker` (run many in parallel,
  all writing to one datastore).
- **injection_probe:** SSTI (template arithmetic), CRLF/header injection,
  reflected-XSS-context, and web-cache-deception candidate detection with benign
  markers.

### Added (CMS, GraphQL, JWT, redirects, Docker)
- **cms_enum:** WordPress/Drupal/Joomla version, user enumeration (WP REST API),
  and exposure checks (xmlrpc, Drupal CHANGELOG).
- **graphql:** full introspection dump (flagging destructive/admin mutations) and
  field-suggestion harvesting when introspection is disabled.
- **jwt_analysis:** finds and decodes JWTs, flagging alg:none, missing expiry, and
  authorization claims.
- **open_redirect:** confirms open redirects by testing redirect-style parameters
  with a harmless canary destination.
- **reverse_ip:** reverse-IP hosting lookup to find co-hosted domains.
- **dork_report:** generates ready-to-run Google/GitHub/Shodan/Censys dork URLs.
- **Docker image:** bundles VoidRecon with dns-helix, paramvoid, and ProjectDiscovery
  tools plus a headless browser (multi-stage Dockerfile).

### Added (real-world recon methodologies)
- **whois_rdap:** domain registration intel via RDAP (registrar/registrant/dates/
  nameservers) — the modern, non-deprecated successor to WHOIS; attribution pivot.
- **dns_advanced:** zone-transfer (AXFR) attempts and SPF include-chain mining.
- **tls_certs:** live TLS-certificate SAN harvesting (finds hosts not in CT logs).
- **vhost:** virtual-host discovery via Host-header fuzzing on web IPs.
- **csp_mining:** related-hostname extraction from CSP and security headers.
- **sourcemaps:** recovers source from exposed JavaScript `.map` files.
- **http_methods:** audits enabled HTTP verbs (PUT/DELETE/TRACE/PATCH).
- **takeover_verify:** active subdomain-takeover confirmation against provider
  fingerprints (can-i-take-over-xyz).
- **shodan_host:** enriches discovered IPs with Shodan (ports/banners/CVEs), no
  packets to the target.
- `cryptography` added to the `full` extra (for TLS SAN parsing).

### Added (live UX, resumability, param discovery, integrations)
- **Live progress checklist:** a real-time terminal table of every module by phase
  with status/elapsed/assets and running totals (`--no-live` to disable).
- **Resumable runs:** per-module datastore checkpointing and `run --resume <id>`
  to continue an interrupted engagement from the next unfinished module.
- **Web UI:** `voidrecon serve` browses the SQLite datastore (runs/assets/findings)
  via a read-only, localhost, stdlib HTTP server.
- **param_discovery:** native reflected + accepted (Arjun-style) parameter
  discovery; bundled wordlist from paramvoid; uses the `paramvoid` binary if present.
- **vuln_hints:** classifies parameterised URLs into SQLi/XSS/SSRF/LFI/RCE/redirect/
  SSTI/IDOR/debug candidate buckets (parameter sets distilled from GF_Patterns).
- **Integrations:** bundled dns-helix resolver list used across all DNS modules;
  `dns-helix`, `paramvoid`, and `sourcemapper` registered as orchestratable tools.
- Asset/Finding gained `from_dict` for checkpoint/DB round-tripping.

### Added
- **Authenticated sessions:** `--header`, `--cookie`, and `--bearer` flags (and an
  `auth` config section) attach credentials to every active request, so the
  crawler, fuzzer, API discovery, and analysis modules can reach behind a login.
  The SPA crawler replays auth headers in the browser context too.
- **Content discovery (`fuzz`):** directory/file brute-force with a bundled
  high-signal wordlist and soft-404 baselining; flags exposed `.git`/`.env`,
  backups, admin panels, and actuator endpoints.
- **Deep tech fingerprinting (`tech_fingerprint`):** curated Wappalyzer-style
  dataset with `implies` chains; enriches the technology list that feeds scoring
  and CVE correlation.
- **Origin-IP discovery (`origin_ip`):** finds WAF/CDN-bypassing origin IPs by
  replaying the target's Host header against discovered IPs.
- **CI:** GitHub Actions workflow running ruff + pytest on Python 3.10–3.12.
- **Dev tooling:** `scripts/setup.sh` and a `Makefile` (`setup`/`test`/`lint`/`run`).

### Changed
- HTTP client accepts session auth headers/cookies and never raises on malformed
  URLs.

## [0.1.0] — Nightfall

### Added
- Core engine: layered config, scope engine (passive-by-default, in-scope gating),
  async throttled HTTP client, de-duplicating datastore, dependency-ordered module
  system, resilient phase pipeline.
- Passive/OSINT: ASN + netblock footprinting, certificate transparency, aggregated
  passive DNS (crt.sh, certspotter, OTX, anubis, hackertarget, urlscan, Censys,
  SecurityTrails, VirusTotal), web archives, GitHub dorking, cloud-bucket
  discovery, DNS/email-security (SPF/DMARC/DKIM/CAA), breach correlation.
- Resolution: DNS resolve, wildcard-aware brute-force + permutations, reverse DNS.
- Active: HTTP probing/fingerprinting, port discovery, native + SPA/XHR crawling,
  JS secret/endpoint mining, API/spec/GraphQL discovery, email harvesting,
  favicon-hash & tracking-ID pivoting (Shodan + Censys), WAF/CDN detection,
  screenshotting.
- Vuln: native version→CVE correlation (auto-refreshable), security-header/CORS/
  cookie analysis, nuclei orchestration, exposed-app flags.
- Intelligence: heuristic scoring, correlation, optional provider-agnostic LLM.
- Reporting: JSON/Markdown/HTML + screenshot gallery; SQLite persistence; run
  diffing; trend dashboard; Slack/Discord completion webhooks.
- CLI: `run`, `modules`, `scope`, `diff`, `dashboard`, `update-cve`.
- Aggressive mode with a confirmation gate.
