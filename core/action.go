// Package core defines the pure domain types for SafeCall.
// This package has zero external dependencies — every other SDK package
// imports core, but core imports nothing from the SDK.
package core

// Action represents the enforcement action the gateway will take.
type Action int

const (
	// ActionAllow passes arguments through untouched.
	ActionAllow Action = iota
	// ActionBlock prevents execution and returns an error to the caller.
	ActionBlock
	// ActionRedact mutates arguments (masks PII/secrets) before execution.
	ActionRedact
	// ActionInterrupt pauses execution for Human-in-the-Loop approval.
	ActionInterrupt
)

// String returns the human-readable name of the action.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionBlock:
		return "BLOCK"
	case ActionRedact:
		return "REDACT"
	case ActionInterrupt:
		return "INTERRUPT"
	default:
		return "UNKNOWN"
	}
}

// ParseAction converts a string to an Action. Returns ActionBlock for
// unrecognised strings (fail-closed).
func ParseAction(s string) Action {
	switch s {
	case "ALLOW", "allow":
		return ActionAllow
	case "BLOCK", "block":
		return ActionBlock
	case "REDACT", "redact":
		return ActionRedact
	case "INTERRUPT", "interrupt":
		return ActionInterrupt
	default:
		return ActionBlock // fail-closed
	}
}
