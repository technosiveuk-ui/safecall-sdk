// Package sdk provides the public API surface for the SafeCall Go SDK.
// It exposes a Builder pattern for configuration and convenience
// constructors for common setups.
//
// Example:
//
//	gw := sdk.New().
//	    StrictDefaults().
//	    BuiltinDLP().
//	    StdoutAudit().
//	    Build()
//
//	secured := sdk.FuncInvoker("query_db", gw, queryDatabase)
package sdk

import (
	"github.com/safecall-dev/safecall-go-sdk/audit"
	"github.com/safecall-dev/safecall-go-sdk/core"
	"github.com/safecall-dev/safecall-go-sdk/gateway"
	"github.com/safecall-dev/safecall-go-sdk/inspection"
	"github.com/safecall-dev/safecall-go-sdk/policy"
)

// Re-export core types for convenience so users only need to import "sdk".
const (
	ActionAllow     = core.ActionAllow
	ActionBlock     = core.ActionBlock
	ActionRedact    = core.ActionRedact
	ActionInterrupt = core.ActionInterrupt
)

// Builder configures and constructs a Gateway.
type Builder struct {
	strictDefaults bool
	defaultAction  core.Action
	policyProvider policy.Provider
	inspectors     []inspection.Inspector
	emitter        audit.Emitter
	useBuiltinDLP  bool
}

// New returns a new Builder with safe defaults.
func New() *Builder {
	return &Builder{
		defaultAction: core.ActionBlock,
	}
}

// StrictDefaults enables strict-defaults mode. Tools without explicit
// policies will be subject to the default action (BLOCK unless overridden
// with StrictDefaultAction).
func (b *Builder) StrictDefaults() *Builder {
	b.strictDefaults = true
	return b
}

// StrictDefaultAction overrides the default action for unmapped tools.
// Only meaningful when StrictDefaults is enabled.
func (b *Builder) StrictDefaultAction(action core.Action) *Builder {
	b.defaultAction = action
	return b
}

// BuiltinDLP registers the built-in RegexInspector and FieldNameInspector.
func (b *Builder) BuiltinDLP() *Builder {
	b.useBuiltinDLP = true
	return b
}

// StdoutAudit sets the audit emitter to write JSON events to stdout.
func (b *Builder) StdoutAudit() *Builder {
	b.emitter = audit.NewStdoutEmitter()
	return b
}

// WithPolicyProvider sets a custom policy provider.
func (b *Builder) WithPolicyProvider(p policy.Provider) *Builder {
	b.policyProvider = p
	return b
}

// WithAuditEmitter sets a custom audit emitter.
func (b *Builder) WithAuditEmitter(e audit.Emitter) *Builder {
	b.emitter = e
	return b
}

// WithInspector adds a custom inspector to the inspection pipeline.
func (b *Builder) WithInspector(i inspection.Inspector) *Builder {
	b.inspectors = append(b.inspectors, i)
	return b
}

// Build constructs the Gateway from the builder configuration.
func (b *Builder) Build() *gateway.Gateway {
	// Build evaluator.
	var evalOpts []policy.EvaluatorOption
	if b.strictDefaults {
		evalOpts = append(evalOpts, policy.WithStrictDefaults())
		evalOpts = append(evalOpts, policy.WithDefaultAction(b.defaultAction))
	}
	eval := policy.NewEvaluator(b.policyProvider, evalOpts...)

	// Build inspector registry.
	inspectors := make([]inspection.Inspector, 0, len(b.inspectors)+2)
	if b.useBuiltinDLP {
		inspectors = append(inspectors, inspection.NewRegexInspector())
		inspectors = append(inspectors, inspection.NewFieldNameInspector())
	}
	inspectors = append(inspectors, b.inspectors...)

	var reg *inspection.Registry
	if len(inspectors) > 0 {
		reg = inspection.NewRegistry(inspectors...)
	}

	// Default emitter.
	emitter := b.emitter
	if emitter == nil {
		emitter = audit.NopEmitter{}
	}

	return gateway.New(eval, reg, emitter)
}
