package assume

import (
	"os"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// assume resolves a template per provider, so tests need the in-repo bundle
// (aws/github/ssh/…) loaded through the normal search path.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()
	os.Exit(m.Run())
}
