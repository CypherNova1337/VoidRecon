# VoidRecon

Maps a target's attack surface the way an intruder would — and keeps you inside scope while it does.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square)
![modules](https://img.shields.io/badge/modules-50-informational?style=flat-square)

## What it does

Recon is usually a pipeline you assembled yourself: subfinder into httpx into
katana into nuclei, glued with shell, with results in a dozen text files. It
works, but nothing in it understands the engagement. It doesn't know what's in
scope. It can't tell you which of four thousand findings matters. And when it
dies at hour three, you start over.

VoidRecon is that pipeline as one engine. Fifty modules across seven phases —
scope, passive, resolve, active, content, vuln, intel — each feeding the next,
with everything landing in one datastore instead of scattered files.

Three things make it different from a script. It has a **scope conscience**:
scope is a first-class input, and modules won't touch what you excluded. It
**scores** what it finds rather than emitting everything equally, with a
built-in analyst that reasons about what to look at next. And runs are
**resumable and comparable** — you can diff today's run against last month's and
see exactly what appeared.

It is passive by default. Active modules only run when you ask for them.

## Why you'd use it

- **Scope is enforced, not documented.** Excluded hosts don't get probed
  because the engine won't do it.
- **Passive until told otherwise** — safe to point at a new target before you
  know what you're allowed to touch.
- **Findings are ranked**, with reasoning, instead of arriving as an
  undifferentiated wall.
- **Resumable**, and diffable against previous runs so you can see what changed.
- **Organisation-first**, looking at the company's whole footprint rather than
  one domain.
- **Reports you can hand over**, plus a local web UI and trend dashboards.

## Install

```bash
git clone https://github.com/CypherNova1337/VoidRecon
cd VoidRecon
pip install .
```

Needs Python 3.10 or newer. Then:

```bash
voidrecon setup
```

Walks through API keys and notification settings, saved to your user config.

## Usage

If you're new to it, let it ask:

```bash
voidrecon wizard
```

A few questions, then it runs. Otherwise:

```bash
voidrecon run example.com
```

Passive by default — nothing touches the target.

**Check your scope before running anything**

```bash
voidrecon scope -T targets.txt -x '*.dev.example.com'
```

Shows the effective scope without running a single module. Do this first on any
engagement with a complicated scope.

**Turn on active modules**

```bash
voidrecon run example.com --active -p standard
```

**Pick an intensity**

```bash
voidrecon run example.com -p quick      # fast pass
voidrecon run example.com -p deep       # thorough
voidrecon run example.com -p stealth    # slow and quiet
```

**Work a bounty program's scope**

```bash
voidrecon run -u https://hackerone.com/example --import-scope
```

Fetches and merges the program's scope. Never probes the target to do it.

**Only certain phases or modules**

```bash
voidrecon run example.com --phases passive,resolve
voidrecon run example.com --only crtsh,wayback
voidrecon modules                        # see what's available
```

**Resume, and compare**

```bash
voidrecon run --resume RUN_ID
voidrecon diff RUN_A RUN_B
voidrecon dashboard example.com
```

**Browse results**

```bash
voidrecon serve
```

## Commands

| Command | What it's for |
|---|---|
| `run` | Run an engagement |
| `wizard` | Guided setup that asks, then runs |
| `scope` | Show effective scope without running anything |
| `modules` | List the 50 modules and their phases |
| `diff` | Compare two runs — what appeared, what went away |
| `dashboard` | Build an HTML trend dashboard across runs |
| `serve` | Browse the datastore in a local web UI |
| `queue` / `worker` | Distribute work across several machines |
| `setup` | Configure API keys and notifications |
| `update` / `update-cve` | Update the tool and CVE signatures |

### Key run options

| Flag | Default | What it does |
|---|---|---|
| `targets` | — | Seed domains, IPs or CIDRs |
| `-T` | — | File of targets, one per line |
| `-i` / `-x` | — | Add an in-scope / out-of-scope entry |
| `-S` | — | Scope file |
| `--import-scope` | off | Merge scope from a program page given by `-u` |
| `--active` | **off** | Enable probing and scanning modules |
| `-A` | off | Maximum coverage — loud, and asks first |
| `-p` | `standard` | `passive`, `quick`, `standard`, `deep`, `stealth` |
| `--phases` | all | Comma list of phases to run |
| `--only` | all | Comma list of specific modules |
| `--rps` / `--concurrency` | — | Throughput limits |
| `-H` / `--cookie` / `--bearer` | — | Authenticate as a logged-in user |
| `--login-url` / `--login-user` / `--login-pass` | — | Form login |
| `--ai` / `--llm` | off | LLM analysis on top of the built-in advisor |
| `--formats` | — | Report formats to write |
| `--resume` | — | Continue a previous run |
| `-o` | `runs/` | Output directory |

## Good to know

- **`--active` is the line.** Without it, nothing touches the target. With it,
  you are scanning. Know which side you're on before you run it.
- **`-A` is genuinely loud.** Maximum coverage, every opt-in module, heavier
  throughput. It asks for confirmation for a reason.
- **Run `scope` first on anything complicated.** Five seconds there beats
  explaining why you probed an excluded host.
- **Authenticate when you can.** An authenticated crawl sees a different
  application, and it's usually the more interesting one.
- **Scoring is a priority hint, not a verdict.** It sorts your queue; it doesn't
  confirm bugs.
- **Fifty modules produce a lot.** Start with `-p quick` to see the shape of a
  target before committing to `deep`.

## Authorised use

Only against targets you own or that are in scope for an engagement or bounty
programme you're part of. The scope features exist to help you stay inside the
agreement — they don't create one.

## License

MIT — see [LICENSE](LICENSE). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
