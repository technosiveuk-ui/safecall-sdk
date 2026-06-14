package core

import "fmt"

// InterruptError is a pure-Go domain error returned when the policy engine
// decides a tool call requires Human-in-the-Loop approval. This error is
// translated into Eino's compose.Interrupt by the adapter/eino ACL — the
// gateway and SDK layers never import Eino directly.
type InterruptError struct {
	// CheckpointID uniquely identifies this paused execution.
	CheckpointID string
	// ToolName is the name of the tool that was interrupted.
	ToolName string
	// Reason explains why human approval is required.
	Reason string
}

// Error implements the error interface.
func (e *InterruptError) Error() string {
	return fmt.Sprintf("safecall: tool %q interrupted (checkpoint=%s): %s",
		e.ToolName, e.CheckpointID, e.Reason)
}

// PolicyLoadError is returned when the policy file cannot be loaded
// (missing, bad permissions, parse errors).
type PolicyLoadError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *PolicyLoadError) Error() string {
	return fmt.Sprintf("safecall: failed to load policy file %q: %v", e.Path, e.Err)
}

// Unwrap supports errors.Is / errors.As.
func (e *PolicyLoadError) Unwrap() error {
	return e.Err
}

// BlockedError is returned to callers when a tool call is blocked.
type BlockedError struct {
	ToolName string
	Reason   string
}

// Error implements the error interface.
func (e *BlockedError) Error() string {
	return fmt.Sprintf("safecall: tool %q blocked: %s", e.ToolName, e.Reason)
}
