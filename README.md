# secretsweep

`secretsweep` is a local-first CLI secret scanner for repositories and config files. It scans for exposed credentials before code is committed or pushed, runs fully offline, and never sends code, file contents, or metadata over the network.

## Install

```bash
pip install secretsweep
```

This package is implemented in pure Python, so `pip install secretsweep` works cleanly on macOS, Linux, and Windows with Python 3.11+.

## Commands

```bash
secretsweep scan .                   # Scan entire repo
secretsweep scan . --staged          # Scan only staged files
secretsweep scan . --json            # Machine-readable output for CI
secretsweep scan . --entropy 4.2     # Tune entropy threshold
secretsweep scan . --allowlist patterns.toml
secretsweep scan . --baseline .secretsweep-baseline.json
secretsweep scan . --write-baseline .secretsweep-baseline.json
secretsweep scan . --redact          # Redact findings in scanned files
secretsweep redact .env              # Redact a single file in place
secretsweep install-hook             # Install as a pre-commit hook
secretsweep init                     # Generate a starter secretsweep.toml
```

## Detection

`secretsweep` uses two detection layers:

1. Regex-based rules for known credential formats such as AWS keys, GitHub tokens, Slack tokens, private keys, JWTs, database URLs, and generic API credential assignments.
2. Shannon entropy scoring for suspicious high-entropy values in assignments and config values.

Severity levels:

- `HIGH`: known secret pattern
- `MEDIUM`: high-entropy suspicious value
- `LOW`: sensitive variable name with a non-empty value

## Output

Human-readable output is the default:

```text
Scanning 142 files...

──────────────────────────────────────────────
 HIGH  .env:4
──────────────────────────────────────────────
Possible database URL detected

 postgres://admin:password123@prod-db.example.com:5432/app

 Recommendation:
   - Rotate this credential immediately
   - Move it to a secrets manager
   - Add the source file to ignore rules if appropriate
```

Use JSON for CI or automation:

```bash
secretsweep scan . --json
```

Exit codes:

- `0`: no findings at the configured fail threshold
- `1`: findings present
- `2`: usage or runtime error

## Configuration

Run:

```bash
secretsweep init
```

This writes `secretsweep.toml`:

```toml
[scan]
entropy_threshold = 4.5
min_secret_length = 20
exclude_paths = ["vendor/", "node_modules/", "*.lock", "*.sum"]

[allowlist]
patterns = [
  "example\\.com",
  "placeholder_key"
]
files = [
  "tests/fixtures/fake_credentials.env"
]

[rules]
aws = true
github = true
slack = true
jwt = true
database_urls = true
private_keys = true
generic_api_keys = true
high_entropy = true
```

`--allowlist` accepts TOML, YAML, or JSON files. The file may either contain a top-level `allowlist` section or just `patterns` and `files`.

## Baselines

Generate a baseline from current findings:

```bash
secretsweep scan . --write-baseline .secretsweep-baseline.json
```

Then compare future scans against it:

```bash
secretsweep scan . --baseline .secretsweep-baseline.json
```

Only new findings are reported.

## Pre-Commit Hook

Install the hook:

```bash
secretsweep install-hook
```

This writes `.git/hooks/pre-commit` and runs:

```bash
secretsweep scan . --staged --json
```

The hook blocks the commit when `HIGH` severity findings are present and prints the affected file, line, and rule.

## GitHub Actions

```yaml
- name: Run secretsweep
  run: |
    pip install secretsweep
    secretsweep scan . --json > results.json
    cat results.json
```

Because findings return exit code `1`, the step fails automatically when secrets are detected.

This repository also includes a CI workflow at `.github/workflows/ci.yml` that:

- installs the package on Python 3.11 and 3.12
- runs the `unittest` suite
- verifies the installed `secretsweep` entrypoint
- builds sdist and wheel artifacts

Release automation is defined in `.github/workflows/release.yml`. Pushing a tag like `v0.1.1` runs the test suite, builds the package, and attaches the build artifacts to a GitHub Release.

## Development

Run the local verification flow with:

```bash
python -m pip install -e .
PYTHONPATH=src python -m unittest -v
PYTHONPATH=src python -m secretsweep scan . --json
```

Or use the included shortcuts:

```bash
make install-dev
make test
make scan
make build
```

## Releases

Current package version: `0.1.1`

Recommended release flow:

```bash
make test
make build
git tag v0.1.1
git push origin v0.1.1
```

For the next release, update the version in `pyproject.toml` and `src/secretsweep/__init__.py`, add a changelog entry in `CHANGELOG.md`, then create and push the new `vX.Y.Z` tag.

## Safety Guarantees

- No network calls during scanning
- No telemetry or analytics
- No reads outside the scan target
- No file modifications unless `--redact` or `redact` is used
- No persistent storage of secrets beyond current process output
