package buildinfo

import "testing"

func TestSetIsWhatVersionReports(t *testing.T) {
	old := stamped
	t.Cleanup(func() { stamped = old })
	Set("v9.9.9-test")
	if got := Version(); got != "v9.9.9-test" {
		t.Errorf("Version() = %q after Set", got)
	}
	Set("") // an empty stamp must not erase a real one
	if got := Version(); got != "v9.9.9-test" {
		t.Errorf("an empty Set overwrote the version: %q", got)
	}
}
