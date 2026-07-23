package main

import (
	"os"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// Load the in-repo curated template bundle so `akasha template` command tests
// can explain/validate against the real shipped providers.
func TestMain(m *testing.M) {
	os.Setenv("AKASHA_TEMPLATES_PATH", template.BundleDirForTest())
	template.ResetForTest()
	os.Exit(m.Run())
}
