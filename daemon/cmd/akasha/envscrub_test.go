package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// The AWS CLI's lookup order puts static environment variables ahead of
// credential_process. A run that inherited AWS_ACCESS_KEY_ID from the launching
// shell would therefore never call the broker and would hand the agent a
// plaintext key in `env`. The shipped bundle must declare these, and the scrub
// must remove exactly them.
func TestCredentialEnvNamesFromShippedBundle(t *testing.T) {
	names := template.CredentialEnvNames()
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN"} {
		if !have[want] {
			t.Errorf("shipped templates do not declare %s as a credential variable; got %v", want, names)
		}
	}
	// Names that are configuration, not credentials, must not be on the list:
	// removing AWS_PROFILE or HOME would break the tool rather than protect it.
	for _, notWant := range []string{"AWS_PROFILE", "AWS_CONFIG_FILE", "HOME", "PATH", "AKASHA_AGENT_KEY"} {
		if have[notWant] {
			t.Errorf("%s is on the credential list and would be scrubbed", notWant)
		}
	}
}

func TestScrubCredentialEnv(t *testing.T) {
	env := []string{
		"HOME=/home/u",
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_PROFILE=dev",
		"GITHUB_TOKEN=ghp_example",
		"AWS_ACCESS_KEY_ID_BACKUP=keep-me", // prefix match must not count
		"aws_access_key_id=lowercase-is-a-different-variable",
	}
	kept, removed := scrubCredentialEnv(env, []string{"AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "NOT_SET"})
	if want := []string{"AWS_ACCESS_KEY_ID", "GITHUB_TOKEN"}; !reflect.DeepEqual(removed, want) {
		t.Fatalf("removed %v, want %v", removed, want)
	}
	if want := []string{"HOME=/home/u", "AWS_PROFILE=dev", "AWS_ACCESS_KEY_ID_BACKUP=keep-me",
		"aws_access_key_id=lowercase-is-a-different-variable"}; !reflect.DeepEqual(kept, want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	// Negative control: nothing to remove leaves the environment byte-identical
	// and prints nothing.
	var out bytes.Buffer
	clean := scrubInheritedCredentials([]string{"HOME=/home/u", "AWS_PROFILE=dev"}, "run", &out)
	if len(clean) != 2 || out.Len() != 0 {
		t.Fatalf("clean env changed or produced output: %v %q", clean, out.String())
	}
	out.Reset()
	scrubInheritedCredentials([]string{"AWS_SECRET_ACCESS_KEY=x"}, "run", &out)
	if !strings.Contains(out.String(), "AWS_SECRET_ACCESS_KEY") || strings.Contains(out.String(), "=x") {
		t.Fatalf("the notice must name the variable and never its value: %q", out.String())
	}
}
