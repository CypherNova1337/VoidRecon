# Changelog

All notable changes to VoidRecon are documented here. Maintained by VoidSec-Hub.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
This project is pre-1.0 and under active development; interfaces may change.

## [Unreleased]

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
