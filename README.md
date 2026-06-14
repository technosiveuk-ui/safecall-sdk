# SafeCall Go SDK

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/safecall-dev/safecall-go-sdk.svg)](https://pkg.go.dev/github.com/safecall-dev/safecall-go-sdk)

**Secure your AI agent tool calls in under 5 minutes and 5 lines of code.**

SafeCall is an open-source, in-process Go library that acts as a security enforcement engine for AI agent tool calls. Instead of running a separate network proxy, import this SDK to wrap your native Go functions and instantly gain:

- 🔒 **PII Redaction** — SSN, credit card, email detection with field-level attribution
- 🛡️ **Secret Blocking** — Catches API keys, tokens, JWTs, and AWS credentials
- 📋 **Policy Enforcement** — ALLOW / BLOCK / REDACT / INTERRUPT per tool
- 📝 **Audit Logging** — Structured audit events via pluggable emitters
- 🚨 **Strict Defaults** — Fail-closed posture for unmapped tools
- ⚡ **Sub-millisecond overhead** — Pure Go hot path, zero framework involvement

## Quick Start

### Install

```bash
go get github.com/safecall-dev/safecall-go-sdk
```

### Secure a Function in 5 Lines

```go
package main

import (
    "context"
    "fmt"
    "github.com/safecall-dev/safecall-go-sdk/sdk"
)

// Your raw, unprotected function
func queryDatabase(ctx context.Context, args map[string]any) (string, error) {
    return fmt.Sprintf("Result for: %v", args), nil
}

func main() {
    // 1. Build the security engine
    gw := sdk.New().
        StrictDefaults().        // Unmapped tools default to BLOCK
        BuiltinDLP().            // Load default PII/Secret regexes
        StdoutAudit().           // Log decisions to stdout
        Build()

    // 2. Wrap the function
    securedQueryDB := sdk.FuncInvoker("query_db", gw, queryDatabase)

    // 3. Call it — PII will be redacted, audit events emitted
    result, err := securedQueryDB(context.Background(), map[string]any{
        "ssn":  "123-45-6789",
        "name": "John Doe",
    })
    if err != nil {
        fmt.Printf("Blocked: %v\n", err)
        return
    }
    fmt.Println(result)
}
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                     sdk.Builder                      │
│  New().StrictDefaults().BuiltinDLP().Build()         │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│                    gateway.Gateway                    │
│  inspect → evaluate → (allow|block|redact) → audit   │
│                                                      │
│  ⚡ Pure Go hot path — ZERO Eino framework imports   │
└──────────────────────┬──────────────────────────────┘
                       │ INTERRUPT only
┌──────────────────────▼──────────────────────────────┐
│              adapter/eino (ACL Bridge)               │
│  Translates InterruptError ↔ compose.Interrupt       │
└─────────────────────────────────────────────────────┘
```

**Key Design Decisions:**
- **Hot Path Bypass (NFR2):** The ALLOW/BLOCK/REDACT paths are pure Go — no Eino graphs instantiated, targeting <20µs overhead.
- **Anti-Corruption Layer:** Eino types are confined to `adapter/eino/`. The `core/`, `sdk/`, and `gateway/` packages have zero Eino imports.
- **Fail-Closed (NFR3):** Any error in the pipeline defaults to BLOCK. Unrecognized actions are blocked.

## Policy Configuration

Create a `policies.yaml` file (must have `0600` permissions on Unix):

```yaml
tools:
  query_db:
    action: REDACT
    redact_fields:
      - ssn
      - credit_card
  send_slack_message:
    action: ALLOW
  delete_database:
    action: INTERRUPT
```

Load it with:

```go
provider, err := policy.NewYamlProvider("policies.yaml")
gw := sdk.New().
    WithPolicyProvider(provider).
    BuiltinDLP().
    Build()
```

## Open-Core Interfaces

The SDK defines clean interfaces for enterprise extensibility:

| Interface | OSS Implementation | Enterprise (Future) |
|---|---|---|
| `policy.Provider` | `YamlProvider` | `ControlPlaneProvider` |
| `inspection.Inspector` | `RegexInspector`, `FieldNameInspector` | `NightfallInspector` |
| `audit.Emitter` | `StdoutEmitter` | `ControlPlaneEmitter` |
| `approval.Provider` | (interface only) | `SlackProvider`, `TeamsProvider` |

## Running Tests

```bash
# All tests
go test ./...

# Benchmark (verify <20µs hot path)
go test -bench=BenchmarkAllowPath -benchmem ./gateway/
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright (c) 2026 [Technosive Ltd.](https://github.com/technosiveuk-ui)
