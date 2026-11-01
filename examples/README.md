# Examples

`targets.csv` is a mixed batch file. The `type` column is optional; without it osintkit
infers the type per row.

```bash
osintkit batch --file examples/targets.csv --dry-run
osintkit batch --file examples/targets.csv --markdown --out ./reports
```

Single-target equivalents:

```bash
osintkit lookup --email alice@example.com --json
osintkit lookup --username torvalds --only github_profile,username_presence
osintkit lookup --domain example.com --skip tcp_ports
osintkit lookup --company "Example Ltd"
```

Health and housekeeping:

```bash
osintkit doctor
osintkit prune --days 14 --dry-run
```
