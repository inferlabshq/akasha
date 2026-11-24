package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSSHRemoteNote(t *testing.T) {
	remotes := func(string) map[string][]string {
		return map[string][]string{
			"origin": {"git@github.com:o/r.git"},
			"web":    {"https://github.com/o/r.git"},
		}
	}
	gh := []string{"github:work"}
	for _, c := range []struct {
		name   string
		args   []string
		labels []string
		want   bool
	}{
		{"push to an ssh remote", []string{"git", "push"}, gh, true},
		{"named ssh remote", []string{"git", "push", "-q", "origin", "HEAD"}, gh, true},
		{"full path to git", []string{"/usr/bin/git", "fetch", "origin"}, gh, true},
		{"-C and -c before the verb", []string{"git", "-C", "x", "-c", "a=b", "pull"}, gh, true},
		{"scp-like url", []string{"git", "clone", "git@github.com:o/r.git"}, gh, true},
		{"ssh url beats an https remote", []string{"git", "push", "ssh://git@h/o/r", "main"}, gh, true},
		{"named https remote", []string{"git", "push", "web", "main"}, gh, false},
		{"https url beats an ssh remote", []string{"git", "ls-remote", "https://github.com/o/r"}, gh, false},
		{"a local clone", []string{"git", "clone", "/tmp/a:b"}, gh, false},
		{"not a network command", []string{"git", "commit", "-m", "push"}, gh, false},
		{"not git", []string{"aws", "push"}, gh, false},
		{"no git credential wired", []string{"git", "push"}, nil, false},
		{"bare git", []string{"git"}, gh, false},
	} {
		got := sshRemoteNote(c.args, c.labels, remotes)
		if (got != "") != c.want {
			t.Errorf("%s: warned = %v, want %v (%q)", c.name, got != "", c.want, got)
		}
		if c.want && !strings.Contains(got, "github:work") {
			t.Errorf("%s: the warning does not name the credential: %q", c.name, got)
		}
	}
}

// Against a real repository, because the remotes come from git's own output.
func TestGitRemotesReadsARealRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, a := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "git@github.com:o/r.git"}} {
		cmd := exec.Command("git", a...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", a, err, out)
		}
	}
	if note := sshRemoteNote([]string{"git", "-C", dir, "push"}, []string{"github:work"}, gitRemotes); note == "" {
		t.Error("no warning for a repository whose only remote is SSH")
	}
	if note := sshRemoteNote([]string{"git", "-C", t.TempDir(), "push"}, []string{"github:work"}, gitRemotes); note != "" {
		t.Errorf("warned outside a repository: %q", note)
	}
}

func TestRunSSHNote(t *testing.T) {
	ssh := func(string) map[string][]string { return map[string][]string{"o": {"git@h:o/r"}} }
	web := func(string) map[string][]string { return map[string][]string{"o": {"https://h/o/r"}} }
	if n := runSSHNote([]string{"github:work"}, ssh); !strings.Contains(n, "github:work") {
		t.Errorf("no warning for an SSH remote: %q", n)
	}
	if n := runSSHNote([]string{"github:work"}, web); n != "" {
		t.Errorf("warned for an HTTPS remote: %q", n)
	}
	if n := runSSHNote(nil, ssh); n != "" {
		t.Errorf("warned with no git credential granted: %q", n)
	}
}
