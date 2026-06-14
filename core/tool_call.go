package core

// ToolCall represents a single invocation request for a named tool.
type ToolCall struct {
	// Name is the registered tool name, e.g. "query_db".
	Name string `json:"name"`

	// Arguments are the key-value pairs passed to the tool.
	// Values may be nested maps for structured arguments.
	Arguments map[string]any `json:"arguments"`
}
