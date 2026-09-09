# Altlast

Altlast keeps a register of everything you run and how old it is. It knows the
version, how many releases behind you are, and whether that version still
receives security fixes. It doesnt change anything; it reads, records, and
prioritizes and cuts down time for you fixing stuff.

**Status: early development. Usable, incomplete.**

## Why not just an update notifier?

Update notifier tell you a newer tag exists. Which is a useful fact but not
always the deciding one. Altlast asks whether the gap is relevant.
eg. "98 releases behind" vs "Stopped receiving security fixes in November 2025"

## What works

- Discovers containers from the Docker socket
- Resolves the newest comparable tag from the registry, with on-disk caching
- Compares tags by *shape*, so running `1.20` is never told to move to
  `1.25.3`, `1.25-alpine`, or a release candidate
- Distinguishes calendar versions from semantic ones, so a `2021.12.16`
  nightly never outranks `10.8.0`
- Reads the OCI version label when the tag carries no version, so containers
  on `latest` still report a real version
- Reports support lifecycle from endoflife.date, including end-of-life dates
- Records every scan in SQLite, so history accumulates

## What does not work yet

- No web dashboard
- No vulnerability or exploitation data
- No host OS, kernel, or firmware collection
- No notifications
- Single host only
- Roughly half of a typical stack has no published lifecycle data. Altlast
  reports that as `unknown` rather than implying everything is fine.

## Install

Requires Go 1.24 or newer.

```bash
git clone https://github.com/osk4r8088/altlast.git
cd altlast
make build
./bin/altlast scan
```

## Usage

```bash
altlast collect              # list assets on this host
altlast collect --json       # machine-readable document
altlast scan                 # collect, resolve, enrich, record
altlast scan --no-store      # scan without touching the database
altlast scan --running       # skip stopped containers
```

Data lives in `$XDG_DATA_HOME/altlast/altlast.db`, cache in
`$XDG_CACHE_HOME/altlast/`. Deleting the cache is always safe.

Authentication for registries uses your existing Docker credentials, so a
prior `docker login` is picked up automatically. On Docker Hub this matters:
anonymous requests are rate limited per source IP.

## Design

**Read only, permanently.** Altlast never pulls, updates, restarts, or
modifies anything. That is a design position rather than a missing feature: it
means the tool can point at production without anyone weighing blast radius.

**Shape-aware comparison.** Real registry tags are messy. Comparing across
release lines, variants, and versioning schemes produces noise, and noise is
what makes people stop reading a tool's output.

**Unknown is a valid answer.** Where data does not exist, Altlast says so.

**Snapshot per scan.** Every scan appends a full set of observations rather
than updating in place, so "what did my stack look like in March" stays
answerable.

## Development

```bash
docker compose -f hack/dev-stack.yml create   # deliberately outdated test corpus
make check                                    # fmt, vet, test, lint
make build
```

The dev stack creates containers without starting them. Nothing outdated ever
runs; only metadata is read.

## Acknowledgements

Lifecycle data from [endoflife.date](https://endoflife.date).
Registry access via [go-containerregistry](https://github.com/google/go-containerregistry).

## License

MIT
