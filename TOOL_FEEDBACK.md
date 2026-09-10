# Field Feedback Log

A record of external field reviews of VoidRecon on live authorized engagements,
and the fixes that shipped in response. Maintained by VoidSec-Hub. Reviews are
paraphrased; every item below was verified against a real run before it shipped.

The pattern across these reviews: the architecture was sound from early on, and
the work was in **calibration** — making evidence earn its severity, keeping
attribution honest, and presenting results a client can trust.

---

## Engagement: hytale.com

- Redirect candidates were high value ("jackpot").
- **Fixed:** GitHub secret findings were uninformative and mis-attributed —
  added matched-code fragments, real-secret screening, and owner-only ownership.
- **Fixed:** the live progress timer froze during long modules (Rich auto-refresh).
- **Fixed:** origin-IP discovery matched every CDN edge — added a WAF-signature
  filter so only true origins are flagged.
- **Fixed:** candidate files duplicated the same endpoint per value — deduped by
  injection point so tools (dalfox/sqlmap/nuclei) ingest them cleanly.

## Engagement: kraken.com

- **Fixed (0.5.1):** `origin_ip` ran for days on a large target — a full
  host×IP cross-product with a 20s timeout per dead IP. Bounded the module (top
  hosts, fast fail-timeout, stop-on-found) **and** gave every module a wall-clock
  budget so no single module can ever hang a run again.

## Engagement: fivetran.com

### v0.6.0 review — severity calibration (shipped 0.7.0 "Calibre")
- Secrets: only classified vendor tokens rate HIGH; generic bundle matches are
  INFO candidates and never seed attack plays.
- Sensitive paths: a 401/403 is "access-controlled", not "exposed"; a 200-with-HTML
  on a non-HTML path is a likely SPA catch-all.
- SQLi: error-based made differential (a data company's marketing page mentioning
  "PostgreSQL" no longer trips it); analytics/OAuth params never probed.
- API specs: require real JSON + spec markers; SPA catch-alls are not specs.
- Candidate classifier gained URL-parameter semantics.
- Takeover: lead vs confirmed made distinct; only a verified fingerprint seeds
  the takeover play.
- Analyst became scope- and status-aware; next-steps respect the checkpoint.
- Report restructured: dossiers first, findings collapsed by severity.

### v0.7.0 review — SQLi ghosts (shipped 0.8.0 "Sifter")
- Boolean SQLi false positives on Next.js `/_next/data/*.json` static files.
- **Fixed:** static-asset paths are never injection-probed, and boolean SQLi now
  requires a reproducible differential (SPA rehydration noise is rejected).

### v0.8.0 review — third-party attribution (shipped 0.8.1–0.8.3)
- The crawler followed OAuth redirect chains and attributed third-party docs
  (accounts.google.com) to the target.
- **Fixed (0.8.1):** findings are confined to the scope domain set; off-domain
  hosts are labeled third-party and excluded from dossier scoring.
- **Fixed (0.8.2):** OIDC discovery documents are public-by-design OAuth signals,
  not exposed specs; harvested OAuth URLs become in-scope intel (client_id +
  in-scope redirect hosts). Over-broad benign-param filtering that had swept up
  the open-redirect/SSRF surface was corrected.
- **Fixed (0.8.3):** the "Where to test" pointer always aims at the in-scope
  asset's own surface, never a followed redirect.

### v0.8.x review — client-ready (shipped 0.9.0 "Warrant")
- SQLi effectively clean, attribution and pointers scope-confined, open-redirect
  playbook restored, coverage expanded (SDK/connector repo mining).
- **Fixed:** tentative-only classes never lead the playbook.
- **Fixed:** finding counts are broken down by source so a large total reads as
  a story, not noise.

Verdict: client-ready.
