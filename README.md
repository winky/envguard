# envguard

Detect exposed secrets and credentials in your local environment before they reach AI tools.

## Overview

AI coding tools inherit the parent shell's environment variables at startup. If credentials like `AWS_SECRET_ACCESS_KEY` are exported in `~/.zshrc`, they become accessible within AI tool sessions. `envguard` scans your local environment and reports what could be exposed — before you launch any AI tool.

**Read-only.** No files are modified, deleted, or sent over the network.

## Installation

```bash
# Go install
go install github.com/winky/envguard@latest

# Or download a pre-built binary from GitHub Releases
curl -L https://github.com/winky/envguard/releases/latest/download/envguard-darwin-arm64.tar.gz | tar -xz
sudo mv envguard /usr/local/bin/envguard
```

### macOS Gatekeeper

If the binary is blocked on first run, follow these steps to allow it:

1. Open **System Settings**
2. Go to **Privacy & Security**
3. Click **"Open Anyway"** next to the message "Apple blocked 'envguard' to protect your Mac"

## Usage

```bash
# Default: scan everything and show a text report
envguard

# Show only CRITICAL and HIGH findings
envguard --min-risk high

# Output JSON (useful for CI or scripting)
envguard --json > scan-report.json

# Skip slow scanners
envguard --skip direnv

# Run only the environment variable scanner
envguard --only env
```

## What It Scans

| Scanner | Target | Platform |
|---------|--------|----------|
| `env` | Current shell environment variables | All |
| `shell` | `~/.zshrc`, `~/.bashrc`, `~/.profile`, etc. | All |
| `files` | `~/.aws/`, `~/.kube/config`, `~/.docker/config.json`, etc. | All |
| `launchctl` | `launchctl` setenv variables | macOS only |
| `agents` | `~/Library/LaunchAgents/*.plist` | macOS only |
| `direnv` | `.envrc` files under `$HOME` (depth 4) | All |

## Risk Levels

| Level | Examples |
|-------|---------|
| **CRITICAL** | `*_SECRET_ACCESS_KEY`, `*_PRIVATE_KEY`, `*_PASSWORD`, `DATABASE_URL` |
| **HIGH** | `*_TOKEN`, `*_API_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN` |
| **MEDIUM** | `AWS_ACCESS_KEY_ID`, `AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS` |
| **LOW** | `AWS_REGION`, `AWS_DEFAULT_REGION` |
| **INFO** | Credential file exists (contents not read) |

## Options

```
--json          Output JSON instead of text
--summary       Show counts only
--no-color      Disable ANSI colors (NO_COLOR env var also works)
--skip NAME     Skip a scanner (repeatable)
--only NAME     Run only this scanner (repeatable, mutually exclusive with --skip)
--depth N       Max depth for .envrc traversal (default: 4)
--min-risk LEVEL  Show only findings at or above this level
--quiet         Suppress progress output on stderr
--version
--help
```

## Remediation

If credentials are found in environment variables:

```bash
# Launch an AI tool without inheriting credentials
env -i HOME="$HOME" PATH="$PATH" SHELL="$SHELL" <your-ai-tool>

# Or unset per-directory with direnv
# ~/work/my-project/.envrc
unset AWS_SECRET_ACCESS_KEY GITHUB_TOKEN
```

For long-lived credentials, consider migrating to [aws-vault](https://github.com/99designs/aws-vault) or [1Password CLI](https://developer.1password.com/docs/cli/).

## Limitations

- **fish shell** config files (`~/.config/fish/config.fish`) are not scanned
- **Dynamic `.envrc` expressions** (e.g. `export TOKEN=$(cat ~/.token)`) are not detected — only static `export`/`setenv` patterns are parsed
- **launchctl** scanning requires macOS 12 Monterey or later
- **macOS-only scanners** (`launchctl`, `agents`) are automatically skipped on Linux

## Build

```bash
make build    # build for current platform
make test     # run tests
make release  # cross-compile for darwin/linux × amd64/arm64
```

## License

MIT
