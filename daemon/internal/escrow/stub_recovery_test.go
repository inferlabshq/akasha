package escrow

import (
	"strings"
	"testing"
)

// The stub is the artifact most likely to outlive akasha, so it carries the
// whole recovery procedure rather than a command name.
//
// It used to say only "akasha restore <path>", which is a dead end for anyone
// who finds this file on an inherited machine with no akasha installed. It now
// names where the bytes physically are, what decrypts them, that BOTH halves
// are required, and that there is no path back without one of the two copies of
// the key.
func TestStubCarriesTheRecoveryProcedure(t *testing.T) {
	body := string(StubContent("/home/dev/app/.env"))

	for _, want := range []string{
		"akasha restore /home/dev/app/.env", // the command, with the real path
		"vault.db",                          // where the bytes are
		"-wal",                              // and the half people leave behind
		"keychain",                          // what decrypts them
		".akb",                              // the other copy of the key
		"BOTH HALVES ARE REQUIRED",          // the sentence that prevents a false rescue
		"refuse to run from inside an",      // why an agent cannot undo this
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the stub should mention %q:\n%s", want, body)
		}
	}

	// Still recognisable as a stub, or protect would escrow one over a real
	// envelope and every IsStub caller would misread it.
	if !IsStub([]byte(body)) {
		t.Error("the rewritten stub is no longer recognised as a stub")
	}

	// Every line is a comment. A tool that reads this file as config — an AWS
	// INI, a .env — must see it as empty rather than as garbage values.
	for i, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Errorf("line %d is not a comment, so a parser would read it as data: %q", i+1, line)
		}
	}

	// A backtick closes Go's raw literal and is worse than useless in a file a
	// shell may read. Removing them was a fix, so it gets a test.
	if strings.ContainsRune(body, '`') {
		t.Error("the stub contains a backtick")
	}
}
