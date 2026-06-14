package core

// Finding represents a single sensitive-data detection attributed to a
// specific field in the tool-call arguments or response.
type Finding struct {
	// FieldName is the dot-separated path to the field, e.g. "user.ssn".
	FieldName string `json:"field_name"`

	// Category classifies the finding, e.g. "PII/SSN", "SECRET/API_KEY".
	Category string `json:"category"`

	// OriginalValue is the raw value that triggered the finding.
	OriginalValue string `json:"original_value,omitempty"`

	// RedactedValue is the masked replacement, e.g. "***REDACTED***".
	RedactedValue string `json:"redacted_value,omitempty"`
}

// RedactedPlaceholder is the standard mask applied to redacted values.
const RedactedPlaceholder = "***REDACTED***"
