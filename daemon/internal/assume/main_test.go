package assume

import (
	"os"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// assume resolves a template per provider, so tests need the in-repo bundle
// (aws/github/ssh/…) loaded through the normal search path.
//
// HOME is redirected for the whole package because the session-base candidate
// list ends at ~/.akasha: a test that makes every earlier candidate fail — which
// is exactly what the guard tests do on purpose — otherwise reaches the
// developer's real data directory and tightens its mode as a side effect.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()

	home, err := os.MkdirTemp("", "akasha-assume-home")
	if err != nil {
		panic("test home: " + err.Error())
	}
	os.Setenv("HOME", home)
	// HOME is only the LAST candidate, so redirecting it isolates the tests on a
	// Mac and nowhere else: on Linux $XDG_RUNTIME_DIR and /dev/shm are tried
	// first, and the plaintext credential files these tests write would land in
	// a tmpfs directory shared with every other run on the host and outlive this
	// one. Pinning the base puts them all inside the temp home removed below.
	SetSessionBase(home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// useSessionBase points the session dir at base for one test, then restores the
// base that was in effect — TestMain's temp home, not "". Clearing it instead
// would silently hand every LATER test in this binary the full candidate walk
// again, which is how a package that looks isolated writes credential files to
// /dev/shm from its second guard test onwards.
func useSessionBase(t *testing.T, base string) {
	t.Helper()
	prev := sessionBase
	SetSessionBase(base)
	t.Cleanup(func() { SetSessionBase(prev) })
}
