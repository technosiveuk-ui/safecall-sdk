package inspection

import "regexp"

// Pattern pairs a compiled regex with a human-readable DLP category.
type Pattern struct {
	Regex    *regexp.Regexp
	Category string
}

// BuiltinPatterns is the default set of sensitive-data patterns shipped
// with the SDK. They are compiled once at package init time.
var BuiltinPatterns = []Pattern{
	{
		Regex:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Category: "PII/SSN",
	},
	{
		// 13–19 digit card numbers (Visa, Mastercard, Amex, etc.)
		Regex:    regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
		Category: "PII/CREDIT_CARD",
	},
	{
		Regex:    regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		Category: "PII/EMAIL",
	},
	{
		// AWS access key IDs start with AKIA
		Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Category: "SECRET/AWS_ACCESS_KEY",
	},
	{
		// Generic API key: long hex or base64-ish strings (32+ chars)
		Regex:    regexp.MustCompile(`\b[A-Za-z0-9/+=]{32,}\b`),
		Category: "SECRET/GENERIC_KEY",
	},
	{
		// JWT tokens: three dot-separated base64url segments
		Regex:    regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b`),
		Category: "SECRET/JWT",
	},
}
