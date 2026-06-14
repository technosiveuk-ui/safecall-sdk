package inspection

import (
	"context"
	"testing"
)

func TestRegexInspector_SSN(t *testing.T) {
	ri := NewRegexInspector()
	fields := map[string]any{
		"ssn":  "123-45-6789",
		"name": "John Doe",
	}
	findings, err := ri.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for SSN")
	}
	found := false
	for _, f := range findings {
		if f.FieldName == "ssn" && f.Category == "PII/SSN" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PII/SSN finding on field 'ssn', got: %+v", findings)
	}
}

func TestRegexInspector_Email(t *testing.T) {
	ri := NewRegexInspector()
	fields := map[string]any{
		"contact": "user@example.com",
	}
	findings, err := ri.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for email address")
	}
	if findings[0].Category != "PII/EMAIL" {
		t.Errorf("expected PII/EMAIL, got %s", findings[0].Category)
	}
}

func TestRegexInspector_NestedMap(t *testing.T) {
	ri := NewRegexInspector()
	fields := map[string]any{
		"user": map[string]any{
			"ssn": "123-45-6789",
		},
	}
	findings, err := ri.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding in nested map")
	}
	if findings[0].FieldName != "user.ssn" {
		t.Errorf("expected field path 'user.ssn', got %s", findings[0].FieldName)
	}
}

func TestRegexInspector_NoMatch(t *testing.T) {
	ri := NewRegexInspector()
	fields := map[string]any{
		"greeting": "hello world",
	}
	findings, err := ri.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got: %+v", findings)
	}
}

func TestFieldNameInspector_Password(t *testing.T) {
	fni := NewFieldNameInspector()
	fields := map[string]any{
		"password": "hunter2",
		"username": "admin",
	}
	findings, err := fni.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Category != "SECRET/PASSWORD" {
		t.Errorf("expected SECRET/PASSWORD, got %s", findings[0].Category)
	}
}

func TestFieldNameInspector_ApiKey(t *testing.T) {
	fni := NewFieldNameInspector()
	fields := map[string]any{
		"api_key": "some-key-value",
	}
	findings, err := fni.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for api_key field name")
	}
}

func TestFieldNameInspector_Nested(t *testing.T) {
	fni := NewFieldNameInspector()
	fields := map[string]any{
		"config": map[string]any{
			"token": "abc123",
		},
	}
	findings, err := fni.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for nested 'token' field")
	}
	if findings[0].FieldName != "config.token" {
		t.Errorf("expected 'config.token', got %s", findings[0].FieldName)
	}
}

func TestRegistry_Aggregates(t *testing.T) {
	reg := NewRegistry(NewRegexInspector(), NewFieldNameInspector())
	fields := map[string]any{
		"password": "hunter2",
		"data":     "SSN is 123-45-6789",
	}
	findings, err := reg.Inspect(context.Background(), fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings (regex + field-name), got %d: %+v",
			len(findings), findings)
	}
}
