// Package approval defines the Provider interface for Human-in-the-Loop
// approval workflows. This is the open-core seam for enterprise approval
// backends (Slack, Teams, etc.).
package approval

import (
	"context"
)

// Request represents a pending approval request.
type Request struct {
	// CheckpointID uniquely identifies this paused execution.
	CheckpointID string `json:"checkpoint_id"`
	// ToolName is the tool awaiting approval.
	ToolName string `json:"tool_name"`
	// Reason explains why approval is needed.
	Reason string `json:"reason"`
}

// Response represents a human's decision on an approval request.
type Response struct {
	// Approved is true if the human approved the action.
	Approved bool `json:"approved"`
	// Reason is an optional explanation from the reviewer.
	Reason string `json:"reason,omitempty"`
}

// Provider handles human approval workflows. Implementations must be
// safe for concurrent use.
type Provider interface {
	// RequestApproval sends an approval request and blocks until a
	// response is received or the context is cancelled.
	RequestApproval(ctx context.Context, req Request) (Response, error)
}
