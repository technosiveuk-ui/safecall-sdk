package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
)

// StdoutEmitter writes JSON-serialized audit events to stdout.
// It is safe for concurrent use.
type StdoutEmitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewStdoutEmitter creates an emitter that writes to os.Stdout.
func NewStdoutEmitter() *StdoutEmitter {
	return &StdoutEmitter{enc: json.NewEncoder(os.Stdout)}
}

// NewWriterEmitter creates an emitter that writes to an arbitrary io.Writer.
// Useful for testing.
func NewWriterEmitter(w io.Writer) *StdoutEmitter {
	return &StdoutEmitter{enc: json.NewEncoder(w)}
}

// Emit JSON-encodes the event and writes it as a single line.
func (e *StdoutEmitter) Emit(_ context.Context, event AuditEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(event)
}
