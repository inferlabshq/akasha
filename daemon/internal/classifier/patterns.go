package classifier

import "regexp"

type Pattern struct {
	Name     string
	Category string
	Risk     string
	Re       *regexp.Regexp
}

// builtinPatterns are the default regex rules applied to every classification request.
var builtinPatterns = []Pattern{
	{
		Name:     "SSN",
		Category: "SSN",
		Risk:     "critical",
		Re:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	},
	{
		Name:     "Credit Card",
		Category: "CreditCard",
		Risk:     "critical",
		Re:       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
	},
	{
		Name:     "Email",
		Category: "Email",
		Risk:     "medium",
		Re:       regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
	},
	{
		Name:     "US Phone",
		Category: "Phone",
		Risk:     "medium",
		Re:       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b`),
	},
	{
		Name:     "AWS Access Key",
		Category: "APIKey",
		Risk:     "critical",
		Re:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		Name:     "Generic API Key",
		Category: "APIKey",
		Risk:     "high",
		Re:       regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|access[_\-]?token|secret[_\-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?`),
	},
	{
		Name:     "Password Field",
		Category: "Password",
		Risk:     "high",
		Re:       regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']?(\S{6,})["']?`),
	},
	{
		Name:     "Bank Account",
		Category: "BankAccount",
		Risk:     "critical",
		Re:       regexp.MustCompile(`\b\d{8,17}\b`),
	},
	{
		Name:     "IPv4 Private",
		Category: "IPAddress",
		Risk:     "low",
		Re:       regexp.MustCompile(`\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`),
	},
}

// riskyToolNames are tool names that warrant elevated scrutiny regardless of content.
var riskyToolNames = map[string]string{
	"send_email":    "high",
	"delete_record": "high",
	"charge_card":   "critical",
	"post_message":  "medium",
	"transfer_funds": "critical",
	"send_sms":      "medium",
	"delete_user":   "high",
	"create_user":   "medium",
}
