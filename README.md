# VeX

VeX is a standalone web vulnerability scanner written in Go. It crawls a target application, maps its attack surface, and runs detection modules to find common web vulnerabilities — confirming each finding before reporting it to keep false positives low.

> **Authorized use only.** VeX is built for CTFs, authorized penetration tests, and home-lab security research. Never run it against a target you don't have explicit permission to test.

## Status

Early development — Phase 0 (foundations) complete. See [Roadmap](#roadmap) below.

## Features (planned)

- Async, rate-limited request engine with bounded concurrency
- Scope-enforced crawler with injection point discovery (params, forms, JSON, headers, cookies)
- Detection modules: security headers, XSS, path traversal, SQL injection, command injection, open redirect, common misconfigurations
- Out-of-band (OOB) confirmation for blind vulnerability classes
- JSON, HTML, and SARIF reporting

## Installation

```bash
git clone https://github.com/RodKast/Vex.git
cd Vex
go build ./cmd/scanner
```

## Usage

```bash
go run cmd/scanner/main.go -target https://example.com -timeout 15 -concurrency 10 -rate-limit 100
```

| Flag           | Default | Description                              |
|----------------|---------|-------------------------------------------|
| `-target`      | `""`    | Target URL or IP to scan                  |
| `-timeout`     | `30`    | Per-request timeout in seconds            |
| `-concurrency` | `10`    | Max concurrent requests                   |
| `-rate-limit`  | `100`   | Max requests per second                   |

## Development

```bash
make build   # compile all packages
make test    # run tests
make lint    # run golangci-lint
make fmt     # format code
```

## Project structure

```
cmd/scanner/      entry point
internal/engine/  request engine
internal/crawler/ crawler and attack-surface mapping
internal/checks/  detection modules
internal/oob/     out-of-band confirmation listener
internal/report/  output and reporting
pkg/types/        shared types
```

## Roadmap

- [x] Phase 0 — Foundations
- [ ] Phase 1 — Request engine
- [ ] Phase 2 — Crawler and attack-surface mapping
- [ ] Phase 3 — Check framework
- [ ] Phase 4 — Detection modules
- [ ] Phase 5 — Out-of-band confirmation
- [ ] Phase 6 — Reporting
- [ ] Phase 7 — Hardening, docs, release

## License

TBD
