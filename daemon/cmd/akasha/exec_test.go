package main

import (
	"strings"
	"testing"
)

func TestUpsertEnvReplacesExisting(t *testing.T) {
	// An already-owned agent session exports GIT_CONFIG_GLOBAL; the broker we
	// wire must overwrite it, not sit as a second entry whose resolution is
	// platform-dependent.
	env := []string{
		"PATH=/usr/bin",
		"GIT_CONFIG_GLOBAL=/home/me/.akasha/agents/claude/github.gitconfig",
		"HOME=/home/me",
	}
	env = upsertEnv(env, "GIT_CONFIG_GLOBAL", "/tmp/akasha-exec-1/github.gitconfig")

	got := valuesFor(env, "GIT_CONFIG_GLOBAL")
	if len(got) != 1 {
		t.Fatalf("GIT_CONFIG_GLOBAL must appear exactly once, got %d: %v", len(got), got)
	}
	if got[0] != "/tmp/akasha-exec-1/github.gitconfig" {
		t.Fatalf("broker value must win, got %q", got[0])
	}
	if len(env) != 3 {
		t.Fatalf("replacing must not change env length, got %d", len(env))
	}
}

func TestUpsertEnvAppendsNew(t *testing.T) {
	env := []string{"PATH=/usr/bin"}
	env = upsertEnv(env, "GITHUB_TOKEN", "x")
	if got := valuesFor(env, "GITHUB_TOKEN"); len(got) != 1 || got[0] != "x" {
		t.Fatalf("new key should be appended once: %v", got)
	}
	if len(env) != 2 {
		t.Fatalf("append should grow env to 2, got %d", len(env))
	}
}

// valuesFor returns every value assigned to key in an environ slice, so a test
// can assert a key is not duplicated.
func valuesFor(env []string, key string) []string {
	var out []string
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			out = append(out, strings.TrimPrefix(e, prefix))
		}
	}
	return out
}
