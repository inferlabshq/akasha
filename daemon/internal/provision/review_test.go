package provision

import (
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// The listing is the only place a user can see that two files claimed one
// label and one of them lost. Both rows read "aws:default", and the fields line
// prints NAMES only — deliberately, so no secret reaches a terminal — so
// without the conflict block the two are indistinguishable on screen.
func TestReviewNamesTheShadowedSource(t *testing.T) {
	out := Review([]template.Finding{{
		Provider: "aws",
		Instance: "default",
		Fields:   map[string]string{"access_key_id": "AKIAFAKEID", "secret_access_key": "FAKESECRET"},
		Source:   "~/.aws/credentials",
		Shadowed: []string{"~/.zshrc"},
	}})

	if !strings.Contains(out, "~/.zshrc") {
		t.Errorf("the losing source must be named:\n%s", out)
	}
	if !strings.Contains(out, "not vaulted") {
		t.Errorf("the listing must say the loser is not stored:\n%s", out)
	}
	// The winner is still presented as an ordinary finding.
	if !strings.Contains(out, "~/.aws/credentials") || !strings.Contains(out, "[1] aws:default") {
		t.Errorf("the winning finding must still be listed:\n%s", out)
	}
	// Values never reach the terminal, conflict or not.
	if strings.Contains(out, "AKIAFAKEID") || strings.Contains(out, "FAKESECRET") {
		t.Errorf("a secret reached the listing:\n%s", out)
	}
}

// No conflict, no noise: the block only appears when a choice was made.
func TestReviewIsQuietWithoutAConflict(t *testing.T) {
	out := Review([]template.Finding{{
		Provider: "aws", Instance: "default",
		Fields: map[string]string{"access_key_id": "AKIA1"},
		Source: "~/.aws/credentials",
	}})
	if strings.Contains(out, "not vaulted") {
		t.Errorf("unexpected conflict block:\n%s", out)
	}
}
