package template

import (
	"os"
	"testing"
)

// No providers are compiled into the binary. Tests load the in-repo curated
// bundle (daemon/templates) through the same path production uses, so they see
// aws/github/… exactly as shipped. Individual tests may override
// AKASHA_TEMPLATES_PATH (with t.Setenv) to exercise custom search paths.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", BundleDirForTest())
	ResetForTest()
	os.Exit(m.Run())
}
