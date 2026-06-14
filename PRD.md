Here is the revised PRD, fully incorporating your architectural resolutions, the module path update, and the name change to SafeCall.

***

# Product Requirements Document (PRD): SafeCall Go SDK
**Document Version:** 1.1
**Date:** June 2026
**Status:** Approved for Implementation

## 1. Introduction & Problem Statement

The AI industry is rapidly shifting from conversational chatbots to **autonomous AI agents**. These agents use the Model Context Protocol (MCP) to execute "tools"—API calls that read, write, and delete data in the real world (e.g., querying a database, sending a Slack message, modifying a GitHub issue).

**The Problem:** AI agents are being given the keys to critical infrastructure with zero security guardrails. An agent can be tricked via prompt injection into dropping a production database, or it might inadvertently summarize PII/PCI data and post it to a public channel. 

**The Solution:** We are building the **SafeCall Go SDK**—an open-source (Apache 2.0), in-process Go library that acts as a security enforcement engine for AI agent tool calls. Instead of running a separate network proxy, developers import this SDK to wrap their native Go functions, instantly gaining PII redaction, secret blocking, policy enforcement, and audit logging.

## 2. Product Vision

To become the de facto standard for securing AI agent tool calls in the Go ecosystem. We will achieve ubiquitous adoption via an easy-to-use OSS SDK, while establishing strict architectural seams for a future proprietary Enterprise Control Plane (centralized management, advanced DLP, SSO).

**The Hero Metric:** A developer should be able to secure an existing Go MCP tool function in under 5 minutes and 5 lines of code.

## 3. Target Audience

*   **Go MCP Server Developers:** Engineers building custom MCP servers who want to ship "Secure by Default" tools to their users.
*   **AI Infrastructure Teams:** Teams building internal AI agent frameworks in Go who need a centralized way to enforce safety guardrails around tool usage.

## 4. Core Functional Requirements (FRs)

### FR1: Function Wrapping (`FuncInvoker`)
The SDK must provide a mechanism to intercept standard Go functions. When an MCP server receives a `tools/call` request, the wrapper intercepts it, inspects the arguments, enforces policy, and only executes the underlying Go function if allowed.

### FR2: Policy Evaluation
The SDK must evaluate tool calls against a configured policy. Supported enforcement actions:
*   `ALLOW`: Pass arguments through untouched.
*   `BLOCK`: Prevent execution, return a standard error to the LLM.
*   `REDACT`: Mutate arguments (mask PII/secrets) before execution.
*   `INTERRUPT`: Pause execution and trigger a Human-in-the-Loop (HITL) approval workflow.

### FR3: Argument & Response Inspection (Data Loss Prevention)
The SDK must scan inbound arguments (before execution) and outbound responses (after execution) for sensitive data.
*   **Field-Level Attribution:** Findings must be attributed to specific argument fields (e.g., finding PII inside the `ssn` field). 
*   **Field-Name Catching:** A field named `password` or `api_key` must trigger a finding even if the value doesn't match a standard regex.

### FR4: Audit Emission
Every enforcement decision (Allow, Block, Redact, Interrupt) must emit a structured `AuditEvent`. The SDK must not write directly to files or stdout; it must emit via a pluggable `audit.Emitter` interface.

### FR5: Strict Defaults Mode
The SDK must support a `StrictDefaults()` builder method. When enabled, any tool call without an explicit policy must default to a strict enforcement action. 
*   **Default Behavior:** Out of the box, `StrictDefaults()` defaults to `BLOCK` (safest, fail-closed posture).
*   **Configurability:** Teams requiring a gentler posture may configure the default action via the builder (e.g., `StrictDefaultAction(sdk.ActionRedact)`).

## 5. Non-Functional Requirements (NFRs)

### NFR1: Zero Transport Coupling
The SDK must be purely an in-process logic engine. It must have **zero dependencies** on `net/http`, MCP JSON-RPC serialization, or network listeners. It operates purely on Go types and `context.Context`.

### NFR2: Low Latency (Hot Path Bypass)
The `ALLOW/BLOCK/REDACT` path (99%+ of calls) execution overhead must be sub-millisecond (target <20µs). To achieve this, the hot path must be pure Go logic in `gateway/` with **zero Eino framework involvement**. Eino is strictly reserved for the `INTERRUPT` branch (see Section 6).

### NFR3: Fail-Closed (Security First)
If the policy engine fails to load, or an unresolvable error occurs during inspection, the SDK must default to `BLOCK`. It must never silently allow a tool call to proceed.

### NFR4: Thread Safety
All SDK components (Policy DB, Risk DB, Inspectors) must be safe for concurrent use across multiple goroutines (standard for MCP servers handling parallel tool calls).

### NFR5: Secrets at Rest Discipline
If the SDK is configured to read from local files (e.g., `policies.yaml`), it must refuse to load files that are group- or world-readable. 
*   **Unix-like systems:** Enforce `0600` via `os.FileMode`.
*   **Windows:** Since POSIX permission bits aren't meaningful in the same way, the SDK will document the expectation that the file is restricted to the executing user via Windows ACLs, rather than silently no-oping or adding heavy Win32 API dependencies.

## 6. Internal Architecture: Eino & The Anti-Corruption Layer (ACL)

The SDK uses **CloudWeGo Eino** (`github.com/cloudwego/eino`) under the hood *exclusively* for the `INTERRUPT` (Human-in-the-Loop) workflow. Eino provides the graph orchestration and checkpoint machinery required to pause a tool call indefinitely and resume it later.

**Critical Directive: The Bifurcated Architecture & ACL**
Eino is a strictly internal implementation detail. 

1.  **The Hot Path (Pure Go):** The `ALLOW/BLOCK/REDACT` paths execute purely via `gateway/` logic. No Eino graphs are instantiated, no channels are dispatched. This satisfies NFR2.
2.  **The Interrupt Path (Eino):** Only when a policy evaluates to `INTERRUPT` does the SDK hand off to `adapter/eino` to persist a checkpoint and pause execution. Because a human is being paged, the latency overhead of graph orchestration here is acceptable.
3.  **Zero Public Exposure:** The public API of the SDK MUST NOT expose any Eino types (e.g., `compose.Interrupt`, `schema.Message`, `compose.Graph`) in function signatures, return types, or structs.
4.  **Interrupt Translation:** 
    *   When the policy engine decides to pause execution (`Action: INTERRUPT`), the domain logic returns a pure Go error: `security.InterruptError{CheckpointID: "...", ToolName: "..."}`.
    *   The `adapter/eino` layer catches this domain error and translates it into Eino's `compose.Interrupt` to pause the graph.

## 7. Developer Experience (DX) & API Design

The SDK must use a Builder pattern for configuration and expose convenience constructors for common setups.

**Target Usage Example:**
```go
package main

import (
    "context"
    "github.com/safecall-dev/safecall-go-sdk/sdk"
)

// The developer's raw, unprotected function
func queryDatabase(ctx context.Context, args map[string]any) (string, error) {
    // ... executes SQL ...
    return "Result", nil
}

func main() {
    // 1. Build the security engine
    gw := sdk.New().
        StrictDefaults().           // Unmapped tools default to BLOCK
        // StrictDefaultAction(sdk.ActionRedact). // Optional: gentler posture
        BuiltinDLP().               // Load default PII/Secret regexes
        StdoutAudit().              // Log decisions to stdout
        Build()

    // 2. Wrap the function
    securedQueryDB := sdk.FuncInvoker("query_db", gw, queryDatabase)

    // 3. Register with your MCP server (mcp-go example)
    // mcpServer.AddTool(securedQueryDB)
}
```

## 8. Open-Core Seams (Interface Boundaries)

The SDK is Apache 2.0, but our business model relies on an Enterprise Control Plane. Therefore, features that will eventually become SaaS offerings must be defined as pure Go interfaces in the OSS SDK, with basic local implementations provided for v0.1.

| Interface | OSS v0.1 Implementation | Future Enterprise Implementation |
| :--- | :--- | :--- |
| **`policy.Provider`** | `YamlProvider` (loads from local `policies.yaml`) | `ControlPlaneProvider` (fetches from SaaS API) |
| **`inspection.Inspector`**| `RegexInspector` (standard Go regex) | `NightfallInspector`, `MicrosoftPurviewInspector` |
| **`audit.Emitter`** | `StdoutEmitter`, `OTelEmitter` | `ControlPlaneEmitter` (pushes to centralized SaaS DB) |
| **`approval.Provider`** | `WebhookProvider`, `CLIApproval` | `SlackProvider`, `TeamsProvider` |

*Rule:* No proprietary logic may be merged into the SDK repo; Enterprise implementations will live in a private repository and inject themselves via these interfaces.

## 9. Out of Scope (Do NOT Build)

*   **MCP Transport Layer:** No HTTP servers, SSE handlers, or `stdio` pipes.
*   **UI / Dashboard:** This is a code-level SDK.
*   **Centralized Database:** The SDK holds no state between restarts (state belongs in the Enterprise Control Plane).
*   **Proprietary Integrations:** The SDK only defines the interfaces; it does not contain code for Slack, Teams, Nightfall, or Vault.

## 10. Acceptance Criteria & Verification

1.  **DX Test:** A developer can `go get` the module, wrap a function, and see a blocked call in < 5 minutes.
2.  **Redaction Test:** An argument `{ "ssn": "123-45-6789" }` passed to a wrapped function results in the underlying function receiving `{ "ssn": "***REDACTED***" }`.
3.  **Strict Default Test:** Calling an unregistered tool with `StrictDefaults()` results in a `BLOCK` action out of the box.
4.  **Fail-Closed Test:** Deleting `policies.yaml` mid-execution results in a `BLOCK` action and an error, not a panic or silent allow.
5.  **Permission Test (Unix):** Running the SDK with a `0644` `policies.yaml` results in an immediate startup failure.
6.  **ACL Test:** No import of `github.com/cloudwego/eino` exists in any file within the `sdk/`, `core/`, or `gateway/` directories.
7.  **Benchmark:** `go test -bench` shows `ALLOW` path overhead of < 20µs (verifying the pure-Go hot path bypass).