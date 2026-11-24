package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// A git credential helper is consulted for HTTPS remotes only. Over SSH git
// authenticates with a key and never calls it, so
//
//	akasha exec --with github:work -- git push
//
// in a repository whose remote is SSH brokered nothing, audited nothing and
// said nothing: it looked exactly like a brokered push. That is how a release
// was pushed with an unrecorded key while everyone involved believed otherwise.
//
// This only warns. Which transport a repository uses is the user's choice, and
// refusing would break a push that works.

// gitNetworkVerbs are the subcommands that contact a remote.
var gitNetworkVerbs = map[string]bool{
	"push": true, "pull": true, "fetch": true, "clone": true, "ls-remote": true,
}

// sshRemoteNote returns the warning for a git command that will use SSH, or "".
// remotes reports a repository's remotes by name; it is a parameter so the
// decision can be tested without a repository.
func sshRemoteNote(args, labels []string, remotes func(dir string) map[string][]string) string {
	if len(args) == 0 || len(labels) == 0 || filepath.Base(args[0]) != "git" {
		return ""
	}
	dir, verb, rest := parseGitArgs(args[1:])
	if !gitNetworkVerbs[verb] {
		return ""
	}

	// A URL on the command line wins over any configured remote.
	var urls []string
	name := ""
	for _, a := range rest {
		switch {
		case strings.HasPrefix(a, "-"):
		case strings.Contains(a, "://") || isSSHURL(a):
			urls = append(urls, a)
		case name == "":
			name = a
		}
	}
	if len(urls) == 0 && verb != "clone" {
		all := remotes(dir)
		if u, ok := all[name]; ok {
			urls = u
		} else {
			for _, u := range all {
				urls = append(urls, u...)
			}
		}
	}
	for _, u := range urls {
		if isSSHURL(u) {
			return fmt.Sprintf("akasha: this remote uses SSH, so git will sign in with your own SSH key and\n"+
				"  not with %s. Nothing is brokered or audited for this command. Use an\n"+
				"  https:// remote to go through Akasha.\n", strings.Join(labels, ", "))
		}
	}
	return ""
}

// runSSHNote is the same warning for a run, where the commands are not known in
// advance: it looks at the repository the run starts in.
func runSSHNote(labels []string, remotes func(dir string) map[string][]string) string {
	if len(labels) == 0 {
		return ""
	}
	for _, urls := range remotes("") {
		for _, u := range urls {
			if isSSHURL(u) {
				return fmt.Sprintf("akasha run: this repository has an SSH remote. Git over SSH uses your ssh-agent,\n"+
					"  not %s, so it is neither brokered nor audited, and it fails if the key\n"+
					"  is not loaded there (~/.ssh is hidden in a run).\n", strings.Join(labels, ", "))
			}
		}
	}
	return ""
}

// gitHelperLabels returns the requested labels that reach git only through its
// credential helper, which is the set an SSH remote silently bypasses.
func gitHelperLabels(labels []string, lookup func(string) *template.Template) []string {
	var out []string
	for _, a := range labels {
		provider, _, _ := strings.Cut(a, ":")
		tpl := lookup(provider)
		if !tpl.Brokerable() {
			continue
		}
		for _, d := range tpl.Agent.Own {
			if d.Mechanism == template.MechGitCredentialHelper {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// parseGitArgs finds the directory git will run in (-C, repeatable), the
// subcommand, and what follows it.
func parseGitArgs(args []string) (dir, verb string, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-C" && i+1 < len(args):
			i++
			if filepath.IsAbs(args[i]) {
				dir = args[i]
			} else {
				dir = filepath.Join(dir, args[i])
			}
		case (a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace") && i+1 < len(args):
			i++ // these take a value that is not the subcommand
		case strings.HasPrefix(a, "-"):
		default:
			return dir, a, args[i+1:]
		}
	}
	return dir, "", nil
}

// isSSHURL recognises ssh:// and the scp-like user@host:path. A colon after a
// slash is an ordinary path, which is git's own rule.
func isSSHURL(u string) bool {
	if scheme, _, ok := strings.Cut(u, "://"); ok {
		return scheme == "ssh" || scheme == "git+ssh" || scheme == "ssh+git"
	}
	host, _, ok := strings.Cut(u, ":")
	return ok && strings.Contains(host, "@") && !strings.Contains(host, "/")
}

// gitRemotes asks git itself, so insteadOf rewrites are already applied. Any
// failure is no remotes: this feeds a warning, never a decision.
func gitRemotes(dir string) map[string][]string {
	run := func(args ...string) []string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		return strings.Fields(string(out))
	}
	all := map[string][]string{}
	for _, name := range run("remote") {
		all[name] = append(run("remote", "get-url", "--all", name), run("remote", "get-url", "--push", "--all", name)...)
	}
	return all
}
