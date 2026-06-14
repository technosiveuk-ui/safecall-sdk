package gateway

import (
	"context"
)

// FuncInvoker wraps a standard Go function with gateway security enforcement.
// The returned function has the same signature as the input function and can
// be registered directly with an MCP server.
//
// This is the core of FR1 (Function Wrapping): when the MCP server receives
// a tools/call request, the wrapped function intercepts it, inspects the
// arguments, enforces policy, and only executes the underlying function
// if allowed.
func FuncInvoker(
	toolName string,
	gw *Gateway,
	fn func(ctx context.Context, args map[string]any) (string, error),
) func(ctx context.Context, args map[string]any) (string, error) {
	return func(ctx context.Context, args map[string]any) (string, error) {
		return gw.Process(ctx, toolName, args, fn)
	}
}
