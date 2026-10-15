package sandbox

import "testing"

// Starting a run from inside a folder the sandbox hides gave the agent an
// unreadable working directory; Claude Code died on it with an error naming
// file descriptors. run refuses instead, and this is the question it asks.
func TestHiddenDirFindsTheRuleThatHidesTheWorkingDir(t *testing.T) {
	t.Setenv("HOME", "/Users/me")
	s := Surface("/Users/me/.akasha", "/tmp/akasha-run-1", nil, nil)
	for _, dir := range []string{"/Users/me/.aws", "/Users/me/.aws/sso", "/Users/me/.akasha", "/Users/me/.ssh"} {
		if _, hidden := s.HiddenDir(dir); !hidden {
			t.Errorf("%s is hidden by the sandbox but HiddenDir said no", dir)
		}
	}
	for _, dir := range []string{"/Users/me/src/app", "/Users/me", "/Users/me/.awsome", "/tmp/akasha-run-1"} {
		if r, hidden := s.HiddenDir(dir); hidden {
			t.Errorf("%s is not hidden, but HiddenDir matched %s", dir, r.Path)
		}
	}
}
