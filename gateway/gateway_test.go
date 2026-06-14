package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/safecall-dev/safecall-go-sdk/audit"
	"github.com/safecall-dev/safecall-go-sdk/core"
	"github.com/safecall-dev/safecall-go-sdk/inspection"
	"github.com/safecall-dev/safecall-go-sdk/policy"
)

func newTestGateway(provider policy.Provider, strictDefaults bool, inspectors ...inspection.Inspector) (*Gateway, *bytes.Buffer) {
	var opts []policy.EvaluatorOption
	if strictDefaults {
		opts = append(opts, policy.WithStrictDefaults())
	}
	eval := policy.NewEvaluator(provider, opts...)

	var reg *inspection.Registry
	if len(inspectors) > 0 {
		reg = inspection.NewRegistry(inspectors...)
	}

	var buf bytes.Buffer
	emitter := audit.NewWriterEmitter(&buf)

	gw := New(eval, reg, emitter)
	return gw, &buf
}

func TestProcess_AllowPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"hello": {Action: core.ActionAllow},
	})
	gw, auditBuf := newTestGateway(provider, false)

	called := false
	fn := func(_ context.Context, args map[string]any) (string, error) {
		called = true
		return "world", nil
	}

	result, err := gw.Process(context.Background(), "hello", map[string]any{"name": "test"}, fn)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("expected function to be called")
	}
	if result != "world" {
		t.Errorf("expected 'world', got %q", result)
	}

	// Verify audit was emitted.
	var event audit.AuditEvent
	if err := json.NewDecoder(auditBuf).Decode(&event); err != nil {
		t.Fatalf("no audit event emitted: %v", err)
	}
	if event.Action != core.ActionAllow {
		t.Errorf("expected ALLOW audit, got %v", event.Action)
	}
}

func TestProcess_BlockPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"danger": {Action: core.ActionBlock},
	})
	gw, _ := newTestGateway(provider, false)

	called := false
	fn := func(_ context.Context, _ map[string]any) (string, error) {
		called = true
		return "", nil
	}

	_, err := gw.Process(context.Background(), "danger", map[string]any{}, fn)
	if err == nil {
		t.Fatal("expected error for BLOCK")
	}
	if called {
		t.Error("function should not have been called for BLOCK")
	}

	var blocked *core.BlockedError
	if !errors.As(err, &blocked) {
		t.Errorf("expected BlockedError, got %T: %v", err, err)
	}
}

func TestProcess_RedactPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"query_db": {Action: core.ActionRedact},
	})
	gw, _ := newTestGateway(provider, false, inspection.NewRegexInspector())

	var receivedArgs map[string]any
	fn := func(_ context.Context, args map[string]any) (string, error) {
		receivedArgs = args
		return "ok", nil
	}

	args := map[string]any{"ssn": "123-45-6789", "name": "John"}
	result, err := gw.Process(context.Background(), "query_db", args, fn)
	if err != nil {
		t.Fatal(err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
	if receivedArgs["ssn"] != core.RedactedPlaceholder {
		t.Errorf("expected SSN to be redacted, got %q", receivedArgs["ssn"])
	}
	if receivedArgs["name"] != "John" {
		t.Errorf("expected 'name' to be unchanged, got %q", receivedArgs["name"])
	}
}

func TestProcess_StrictDefaults_Block(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{})
	gw, _ := newTestGateway(provider, true)

	called := false
	fn := func(_ context.Context, _ map[string]any) (string, error) {
		called = true
		return "", nil
	}

	_, err := gw.Process(context.Background(), "unregistered_tool", map[string]any{}, fn)
	if err == nil {
		t.Fatal("expected BLOCK for unregistered tool with strict defaults")
	}
	if called {
		t.Error("function should not have been called")
	}
}

func TestProcess_InterruptPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"delete_db": {Action: core.ActionInterrupt},
	})
	gw, _ := newTestGateway(provider, false)

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		t.Error("function should not be called for INTERRUPT")
		return "", nil
	}

	_, err := gw.Process(context.Background(), "delete_db", map[string]any{}, fn)
	if err == nil {
		t.Fatal("expected InterruptError")
	}

	var ie *core.InterruptError
	if !errors.As(err, &ie) {
		t.Errorf("expected InterruptError, got %T: %v", err, err)
	}
	if ie.ToolName != "delete_db" {
		t.Errorf("expected tool 'delete_db', got %q", ie.ToolName)
	}
}

func TestFuncInvoker(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"greet": {Action: core.ActionAllow},
	})
	gw, _ := newTestGateway(provider, false)

	original := func(_ context.Context, args map[string]any) (string, error) {
		return "hello " + args["name"].(string), nil
	}

	wrapped := FuncInvoker("greet", gw, original)
	result, err := wrapped(context.Background(), map[string]any{"name": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
}

func TestRedactField_Nested(t *testing.T) {
	args := map[string]any{
		"user": map[string]any{
			"ssn": "123-45-6789",
		},
	}
	redactField(args, "user.ssn", core.RedactedPlaceholder)

	user := args["user"].(map[string]any)
	if user["ssn"] != core.RedactedPlaceholder {
		t.Errorf("expected nested field to be redacted, got %q", user["ssn"])
	}
}

// BenchmarkAllowPath verifies NFR2: ALLOW path overhead must be < 20µs.
func BenchmarkAllowPath(b *testing.B) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"fast_tool": {Action: core.ActionAllow},
	})
	eval := policy.NewEvaluator(provider)
	gw := New(eval, nil, audit.NopEmitter{})

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		return "ok", nil
	}
	args := map[string]any{"key": "value"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gw.Process(ctx, "fast_tool", args, fn)
	}
}
