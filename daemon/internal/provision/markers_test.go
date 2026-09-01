package provision

import (
	"strings"
	"testing"
	"time"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

func finding(provider, instance, source string, mod time.Time) template.Finding {
	return template.Finding{
		Provider: provider, Instance: instance, Source: source,
		Fields: map[string]string{"access_key_id": "AKIA…"}, ModTime: mod,
	}
}

// The case the marks exist for: an agent writes a credential file for a
// provider you have never used, and waits for you to run discovery.
func TestNewProviderAndFreshFileAreMarked(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	ctx := ReviewContext{Known: map[string]bool{"aws:default": true}, Now: now}

	out := ReviewWith([]template.Finding{
		finding("aws", "default", "~/.aws/credentials", now.Add(-90*24*time.Hour)),
		finding("gcp", "default", "~/.env", now.Add(-40*time.Second)),
	}, ctx)

	// The one you already had, from a file you have not touched in months.
	if strings.Contains(out, "aws:default   ⚠") {
		t.Errorf("a credential you already vaulted was marked NEW:\n%s", out)
	}
	// The planted one.
	if !strings.Contains(out, "⚠ NEW — no gcp credential vaulted before") {
		t.Errorf("a provider never seen before was not marked:\n%s", out)
	}
	if !strings.Contains(out, "⚠ written 40 seconds ago") {
		t.Errorf("a file written moments ago was not marked:\n%s", out)
	}
	if !strings.Contains(out, "1 marked above") {
		t.Errorf("the summary does not count the marked findings:\n%s", out)
	}
}

// The failure that would make the whole thing useless: on a first run nothing
// is vaulted, so marking every finding NEW would flag the entire list and teach
// the reader to skip the mark before they reach the end of it.
func TestNoContextMarksNothing(t *testing.T) {
	now := time.Now()
	out := ReviewWith([]template.Finding{
		finding("aws", "default", "~/.aws/credentials", now),
		finding("gcp", "default", "~/.env", now),
	}, ReviewContext{})

	if strings.Contains(out, "⚠ NEW") {
		t.Errorf("findings were marked NEW with no knowledge of what is vaulted:\n%s", out)
	}
	if strings.Contains(out, "marked above") {
		t.Errorf("the summary fired with nothing marked:\n%s", out)
	}
	// …and the listing itself is unchanged, so the daemon being down costs the
	// marks and nothing else.
	if !strings.Contains(out, "aws:default") || !strings.Contains(out, "~/.aws/credentials") {
		t.Errorf("the listing lost content when the context was empty:\n%s", out)
	}
}

// A file with no mtime — an env-var finding — must not be described as freshly
// written. The zero time is "unknown", not "just now".
func TestFindingWithNoFileIsNotMarkedFresh(t *testing.T) {
	now := time.Now()
	out := ReviewWith([]template.Finding{
		{Provider: "env", Instance: "STRIPE_KEY", Source: "environment",
			Fields: map[string]string{"value": "sk_…"}},
	}, ReviewContext{Known: map[string]bool{"env:STRIPE_KEY": true}, Now: now})

	if strings.Contains(out, "written") {
		t.Errorf("a finding with no source file was described as recently written:\n%s", out)
	}
}

// A future mtime — a clock skew, a bad archive — must not read as "written in
// the last 30 minutes".
func TestFutureModTimeIsNotMarked(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	out := ReviewWith([]template.Finding{
		finding("aws", "default", "~/.aws/credentials", now.Add(time.Hour)),
	}, ReviewContext{Known: map[string]bool{"aws:default": true}, Now: now})

	if strings.Contains(out, "written") {
		t.Errorf("a file dated in the future was marked as freshly written:\n%s", out)
	}
}

// Review() keeps working for every existing caller, marking nothing.
func TestReviewWithoutContextIsUnchanged(t *testing.T) {
	f := []template.Finding{finding("aws", "default", "~/.aws/credentials", time.Now())}
	if Review(f) != ReviewWith(f, ReviewContext{}) {
		t.Error("Review() and ReviewWith(.., empty) disagree")
	}
}

func TestHumanAge(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5 seconds"},
		{90 * time.Second, "a minute"},
		{12 * time.Minute, "12 minutes"},
	} {
		if got := humanAge(c.d); got != c.want {
			t.Errorf("humanAge(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}

// The failure the unit tests missed and the real command found: a running
// daemon with an empty vault answers /label/list with an EMPTY LIST, not an
// error — so Known is non-nil and empty, and a nil check lets it straight
// through. On that first run every finding is new, and the whole listing gets
// flagged, which is the one outcome that makes the mark worthless.
func TestEmptyKnownSetMarksNothing(t *testing.T) {
	now := time.Now()
	out := ReviewWith([]template.Finding{
		finding("aws", "default", "~/.aws/credentials", now.Add(-90*24*time.Hour)),
		finding("ssh", "id_ed25519", "~/.ssh/id_ed25519", now.Add(-90*24*time.Hour)),
	}, ReviewContext{Known: map[string]bool{}, Now: now})

	if strings.Contains(out, "\u26a0 NEW") {
		t.Errorf("a first run with nothing vaulted marked its findings NEW:\n%s", out)
	}
	if strings.Contains(out, "marked above") {
		t.Errorf("the summary fired on a first run:\n%s", out)
	}
}

// The mark must say which of the two things is new. Claiming "no ssh credential
// vaulted before" on a machine that already has ssh:id_ed25519 is false, and a
// warning that overstates is one people learn to discount.
func TestNewMarkDistinguishesProviderFromInstance(t *testing.T) {
	now := time.Now()
	known := map[string]bool{"ssh:id_ed25519": true}

	out := ReviewWith([]template.Finding{finding("ssh", "id_planted", "~/.ssh/id_planted", now)},
		ReviewContext{Known: known, Now: now})
	if !strings.Contains(out, "no ssh:id_planted vaulted before") {
		t.Errorf("a new INSTANCE of a known provider was described wrongly:\n%s", out)
	}
	if strings.Contains(out, "no ssh credential vaulted before") {
		t.Errorf("the mark claims there is no ssh credential when there is one:\n%s", out)
	}

	// …and a genuinely unseen provider still gets the broader wording.
	out = ReviewWith([]template.Finding{finding("gcp", "default", "~/.config/gcloud/x.json", now)},
		ReviewContext{Known: known, Now: now})
	if !strings.Contains(out, "no gcp credential vaulted before") {
		t.Errorf("a provider never seen before lost the broader wording:\n%s", out)
	}
}

func TestVeryRecentReadsAsMoments(t *testing.T) {
	if got := humanAge(2 * time.Second); got != "moments" {
		t.Errorf("humanAge(2s) = %q, want \"moments\" — \"0 seconds ago\" reads like a bug", got)
	}
}
