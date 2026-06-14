// Package gateway is the hot-path orchestrator for SafeCall. It chains
// inspection → policy evaluation → execution → audit emission.
//
// CRITICAL: This package must have ZERO imports of github.com/cloudwego/eino.
// The ALLOW/BLOCK/REDACT paths execute as pure Go logic here. Only the
// INTERRUPT path is handed off to adapter/eino via the InterruptError
// domain type.
package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/safecall-dev/safecall-go-sdk/audit"
	"github.com/safecall-dev/safecall-go-sdk/core"
	"github.com/safecall-dev/safecall-go-sdk/inspection"
	"github.com/safecall-dev/safecall-go-sdk/policy"
)

// ExecFunc is the signature of the underlying tool function.
type ExecFunc func(ctx context.Context, args map[string]any) (string, error)

// Gateway orchestrates the security enforcement pipeline:
//
//	inspect → evaluate → (allow|block|redact|interrupt) → audit
//
// It is safe for concurrent use.
type Gateway struct {
	evaluator  *policy.Evaluator
	inspectors *inspection.Registry
	emitter    audit.Emitter
}

// New creates a Gateway with the given components.
func New(evaluator *policy.Evaluator, inspectors *inspection.Registry, emitter audit.Emitter) *Gateway {
	if emitter == nil {
		emitter = audit.NopEmitter{}
	}
	return &Gateway{
		evaluator:  evaluator,
		inspectors: inspectors,
		emitter:    emitter,
	}
}

// Process runs the full enforcement pipeline for a single tool call.
//
// Pipeline:
//  1. Pre-inspect arguments for sensitive data
//  2. Evaluate policy (with findings)
//  3. Act on the decision:
//     - ALLOW:     execute with original args
//     - BLOCK:     return BlockedError
//     - REDACT:    mask findings in args, then execute
//     - INTERRUPT: return InterruptError (for ACL translation)
//  4. Post-inspect response
//  5. Emit audit event
func (g *Gateway) Process(ctx context.Context, toolName string, args map[string]any, exec ExecFunc) (string, error) {
	start := time.Now()

	// 1. Pre-inspect arguments.
	var findings []core.Finding
	if g.inspectors != nil {
		var err error
		findings, err = g.inspectors.Inspect(ctx, args)
		if err != nil {
			// Fail-closed: inspection error → BLOCK.
			g.emitAudit(ctx, toolName, core.ActionBlock, findings, start, err)
			return "", &core.BlockedError{
				ToolName: toolName,
				Reason:   fmt.Sprintf("inspection error: %v", err),
			}
		}
	}

	// 2. Evaluate policy.
	decision, err := g.evaluator.Evaluate(ctx, toolName, findings)
	if err != nil {
		// Fail-closed: evaluator error → BLOCK.
		g.emitAudit(ctx, toolName, core.ActionBlock, findings, start, err)
		return "", &core.BlockedError{
			ToolName: toolName,
			Reason:   fmt.Sprintf("policy evaluation error: %v", err),
		}
	}

	// 3. Act on the decision.
	switch decision.Action {
	case core.ActionBlock:
		g.emitAudit(ctx, toolName, core.ActionBlock, findings, start, nil)
		return "", &core.BlockedError{
			ToolName: toolName,
			Reason:   decision.Reason,
		}

	case core.ActionInterrupt:
		checkpointID := fmt.Sprintf("cp_%s_%d", toolName, time.Now().UnixNano())
		g.emitAuditWithCheckpoint(ctx, toolName, core.ActionInterrupt, findings, start, checkpointID)
		return "", &core.InterruptError{
			CheckpointID: checkpointID,
			ToolName:     toolName,
			Reason:       decision.Reason,
		}

	case core.ActionRedact:
		// Mask sensitive values in args before execution.
		redactArgs(args, findings)
		result, execErr := exec(ctx, args)
		g.emitAudit(ctx, toolName, core.ActionRedact, findings, start, execErr)
		return result, execErr

	case core.ActionAllow:
		result, execErr := exec(ctx, args)
		g.emitAudit(ctx, toolName, core.ActionAllow, findings, start, execErr)
		return result, execErr

	default:
		// Unknown action → fail-closed.
		g.emitAudit(ctx, toolName, core.ActionBlock, findings, start, nil)
		return "", &core.BlockedError{
			ToolName: toolName,
			Reason:   fmt.Sprintf("unknown action %v; fail-closed", decision.Action),
		}
	}
}

// redactArgs replaces sensitive values in the argument map with the
// redacted placeholder.
func redactArgs(args map[string]any, findings []core.Finding) {
	for _, f := range findings {
		redactField(args, f.FieldName, core.RedactedPlaceholder)
	}
}

// redactField sets a nested field (dot-separated path) to the given value.
func redactField(m map[string]any, fieldPath string, value string) {
	parts := splitFieldPath(fieldPath)
	current := m
	for i, part := range parts {
		if i == len(parts)-1 {
			// Leaf: replace value.
			current[part] = value
			return
		}
		// Traverse into nested map.
		if nested, ok := current[part].(map[string]any); ok {
			current = nested
		} else {
			return // path doesn't exist, nothing to redact
		}
	}
}

// splitFieldPath splits a dot-separated field path, e.g. "user.ssn" → ["user", "ssn"].
func splitFieldPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}

func (g *Gateway) emitAudit(ctx context.Context, toolName string, action core.Action, findings []core.Finding, start time.Time, execErr error) {
	g.emitAuditWithCheckpoint(ctx, toolName, action, findings, start, "")
	_ = execErr // error is captured in the event if needed
}

func (g *Gateway) emitAuditWithCheckpoint(ctx context.Context, toolName string, action core.Action, findings []core.Finding, start time.Time, checkpointID string) {
	event := audit.AuditEvent{
		Timestamp:    time.Now(),
		ToolName:     toolName,
		Action:       action,
		Findings:     findings,
		CheckpointID: checkpointID,
		Duration:     time.Since(start),
	}
	// Audit emission errors are not fatal — log them but don't break the call.
	_ = g.emitter.Emit(ctx, event)
}
