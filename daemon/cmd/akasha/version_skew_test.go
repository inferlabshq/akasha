package main

import (
	"bytes"
	"strings"
	"testing"
)

// The skew `akasha version` has always described in its help is now something
// it can detect. Two cases matter: a daemon reporting a different build, and a
// daemon reporting NO build -- which only a build older than this one does, so
// absence is itself the evidence.
func TestReportVersionSkew(t *testing.T) {
	for _, tc := range []struct {
		name, health, want string
	}{
		{"same build", `{"status":"ok","version":"v1"}`, ""},
		{"different build", `{"status":"ok","version":"v0"}`, "running v0; this CLI is v1"},
		{"no version key", `{"status":"ok"}`, "OLDER than this CLI"},
	} {
		var buf bytes.Buffer
		reportVersionSkew(&buf, tc.health, "v1")
		if tc.want == "" && buf.Len() != 0 {
			t.Errorf("%s: warned when builds match:\n%s", tc.name, buf.String())
		}
		if tc.want != "" && !strings.Contains(buf.String(), tc.want) {
			t.Errorf("%s: want %q in:\n%s", tc.name, tc.want, buf.String())
		}
	}
}
