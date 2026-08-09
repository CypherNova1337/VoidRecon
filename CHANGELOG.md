# Changelog

All notable changes to VoidRecon are documented here. Maintained by VoidSec-Hub.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
This project is pre-1.0 and under active development; interfaces may change.

## [Unreleased]

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
