package template

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// reloadFixture varies one credential field name, which changes both the
// template's observable shape and its digest.
const reloadFixture = `kind: provider
name: rl
version: 1

credential:
  fields:
    %s: {secret: true}

deliver:
  - mode: env
    env:
      RL_TOKEN: "{%s}"
`

// The registry must notice that a template on disk has changed.
//
// It was a sync.Once: read once, frozen for the life of the process. The trust
// store beside it is read fresh on every request, and store.Approved compares a
// digest taken from DISK against the one frozen here — two halves of one check
// with two different ideas of "now".
//
// The consequence was a provider nothing could repair without a restart. Edit a
// trusted template and the fresh on-disk digest stops matching the stale
// in-memory one, so it reads as untrusted; the error says to approve it, and
// approving it records the new digest against the same frozen copy, so the next
// request fails identically. The remedy the message gives is the thing that was
// just done.
//
// Digest is the assertion because Digest is what trust compares.
func TestRegistryPicksUpAnEditedTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rl.yaml")
	write := func(field string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf(reloadFixture, field, field)), 0600); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("AKASHA_TEMPLATES_PATH", dir)
	// Zero so the check is not deferred by the recheck window; the window is a
	// cost control, not the property under test.
	old := recheckEvery
	recheckEvery = 0
	t.Cleanup(func() { recheckEvery = old })
	ResetForTest()
	t.Cleanup(ResetForTest)

	write("token")
	first := Get("rl")
	if first == nil {
		t.Fatal("template did not load; the rest of this test would prove nothing")
	}
	if _, ok := first.Credential.Fields["token"]; !ok {
		t.Fatalf("expected a `token` field, got %v", first.Credential.Fields)
	}
	beforeDigest := first.Digest()
	if beforeDigest == "" {
		t.Fatal("no digest, so the trust comparison this test is about cannot happen")
	}

	write("rotated")
	second := Get("rl")
	if second == nil {
		t.Fatal("template vanished after an edit")
	}
	if _, ok := second.Credential.Fields["rotated"]; !ok {
		t.Errorf("the registry did not pick up the edit: fields = %v", second.Credential.Fields)
	}
	if second.Digest() == beforeDigest {
		t.Error("the digest is unchanged after an edit — trust would keep comparing a stale value, " +
			"which is what bricked an edited provider until the daemon restarted")
	}

	// A template REMOVED from the search path must go too, or a deleted
	// provider keeps answering.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if Get("rl") != nil {
		t.Error("a deleted template is still being served from the registry")
	}
}

// And the cost control does what it says: with a window set, a lookup does not
// re-read the search path on every call.
func TestRecheckWindowDefersTheNextRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rl.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(reloadFixture, "token", "token")), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AKASHA_TEMPLATES_PATH", dir)

	old := recheckEvery
	recheckEvery = time.Hour
	t.Cleanup(func() { recheckEvery = old })
	ResetForTest()
	t.Cleanup(ResetForTest)

	first := Get("rl")
	if first == nil {
		t.Fatal("initial load failed")
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf(reloadFixture, "rotated", "rotated")), 0600); err != nil {
		t.Fatal(err)
	}
	if got := Get("rl"); got != nil && got.Digest() != first.Digest() {
		t.Error("the recheck window did not defer the read, so it is not bounding the stat cost")
	}
}
