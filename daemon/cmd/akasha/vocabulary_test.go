package main

import (
	"strings"
	"testing"
)

// The old command names keep working. A shell alias, a script, a habit -- all
// of them say `akasha assume` and `akasha whoami`, and none of them must
// break on upgrade.
func TestSessionAndDescribeKeepTheirOldNames(t *testing.T) {
	for old, want := range map[string]string{"assume": "session", "whoami": "describe"} {
		cmd, _, err := rootCmd.Find([]string{old})
		if err != nil {
			t.Fatalf("`akasha %s` no longer resolves: %v", old, err)
		}
		if cmd.Name() != want {
			t.Errorf("`akasha %s` resolved to %q, want %q", old, cmd.Name(), want)
		}
	}
}

// --with and --assume are ONE flag. Mixed in one command line, every value
// lands, in the order typed; and help advertises only the new name.
//
// The failure this guards: two StringArray flags bound to one slice, where
// pflag replaces the slice on each flag's first Set, so `--with a --assume b`
// silently keeps b and loses a -- a credential the user named that is simply
// not there.
func TestWithFlagAcceptsAssumeAndMixesInOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parse func([]string) error
		dst   *[]string
		usage func() string
	}{
		{"exec", execCmd.ParseFlags, &execAssumes, func() string { return execCmd.LocalFlags().FlagUsages() }},
		{"run", runCmd.ParseFlags, &runAssumes, func() string { return runCmd.LocalFlags().FlagUsages() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*tc.dst = nil
			if err := tc.parse([]string{"--with", "aws:default", "--assume", "ssh:gitlab", "--with", "github:work"}); err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := strings.Join(*tc.dst, ",")
			if got != "aws:default,ssh:gitlab,github:work" {
				t.Errorf("values = %q -- a mixed --with/--assume line must keep every value in order", got)
			}
			u := tc.usage()
			if !strings.Contains(u, "--with") || strings.Contains(u, "--assume") {
				t.Errorf("help must advertise --with and not --assume:\n%s", u)
			}
		})
	}
}
