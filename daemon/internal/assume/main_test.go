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
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
