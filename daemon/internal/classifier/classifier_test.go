package classifier_test

import (
	"regexp"
	"testing"

	"github.com/inferlabshq/akasha/internal/classifier"
)

func TestClassifySSN(t *testing.T) {
	clf := classifier.New(nil)
	r := clf.Classify("lookup_account", "Customer SSN is 429-21-0001, please process.")
	if !r.Sensitive {
		t.Fatal("expected sensitive")
	}
	if r.Category != "SSN" {
		t.Fatalf("category: got %s want SSN", r.Category)
	}
	if r.Risk != "critical" {
		t.Fatalf("risk: got %s want critical", r.Risk)
	}
	if r.Value != "429-21-0001" {
		t.Fatalf("value: got %s", r.Value)
	}
}

func TestClassifyCreditCard(t *testing.T) {
	clf := classifier.New(nil)
	r := clf.Classify("charge_card", "card: 4111111111111111")
	if !r.Sensitive {
		t.Fatal("expected sensitive")
	}
	if r.Category != "CreditCard" {
		t.Fatalf("category: got %s", r.Category)
	}
}

func TestClassifyEmail(t *testing.T) {
	clf := classifier.New(nil)
	r := clf.Classify("send_message", "send to user@example.com")
	if !r.Sensitive {
		t.Fatal("expected sensitive")
	}
	if r.Category != "Email" {
		t.Fatalf("category: got %s", r.Category)
	}
}

func TestClassifyRiskyTool(t *testing.T) {
	clf := classifier.New(nil)
	r := clf.Classify("send_email", "Hello world")
	if !r.Sensitive {
		t.Fatal("expected sensitive for risky tool name")
	}
	if r.Category != "RiskyTool" {
		t.Fatalf("category: got %s", r.Category)
	}
}

func TestClassifyClean(t *testing.T) {
	clf := classifier.New(nil)
	r := clf.Classify("get_weather", "London tomorrow morning")
	if r.Sensitive {
		t.Fatal("expected not sensitive")
	}
}

func TestClassifyAPIKey(t *testing.T) {
	clf := classifier.New(nil)
	r := clf.Classify("call_api", `api_key: "sk-abcdefgh1234567890123456789012"`)
	if !r.Sensitive {
		t.Fatal("expected sensitive")
	}
	if r.Category != "APIKey" {
		t.Fatalf("category: got %s", r.Category)
	}
}

func TestClassifyAll(t *testing.T) {
	clf := classifier.New(nil)
	results := clf.ClassifyAll("", "SSN: 429-21-0001, email: foo@bar.com")
	if len(results) < 2 {
		t.Fatalf("expected >=2 results, got %d", len(results))
	}
}

func TestCustomPattern(t *testing.T) {
	extra := []classifier.Pattern{
		{
			Name:     "Acme ID",
			Category: "AcmeID",
			Risk:     "high",
			Re:       regexp.MustCompile(`ACME-\d{6}`),
		},
	}
	clf := classifier.New(extra)
	r := clf.Classify("lookup", "id is ACME-123456")
	if !r.Sensitive || r.Category != "AcmeID" {
		t.Fatalf("custom pattern not matched: %+v", r)
	}
}
