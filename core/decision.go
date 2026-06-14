package core

// Decision is the outcome of policy evaluation for a single tool call.
type Decision struct {
	// Action is the enforcement action to take.
	Action Action `json:"action"`

	// Reason provides a human-readable explanation for the decision.
	Reason string `json:"reason,omitempty"`

	// Findings contains all sensitive-data detections from inspection.
	Findings []Finding `json:"findings,omitempty"`

	// CheckpointID is populated only when Action == ActionInterrupt.
	// It identifies the checkpoint for later resumption.
	CheckpointID string `json:"checkpoint_id,omitempty"`
}
