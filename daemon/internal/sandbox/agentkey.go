package sandbox

import "path/filepath"

// AKASHA'S OWN KEY was the one credential the sandbox did not mask.
//
// `akasha setup` injects AKASHA_AGENT_KEY into each harness's settings file, so
// that every session the harness starts is routed through the daemon. That file
// was absent from the deny surface. Inside `akasha run probe --assume
// aws:default`, ~/.aws and ~/.akasha were correctly masked and the key file was
// readable — so the agent read the persistent key out of a file akasha itself
// had written, presented it to the daemon over loopback, and resolved aws:prod:
// a profile the run was never granted. The run's OWN key was correctly refused
// for the same request.
//
// The capability profile could not save it. runCapabilities is keyed on the run
// IDENTITY, and runForKey returns early unless the agent id carries the `run:`
// prefix, so a persistent key never reaches the profile at all. That keying is
// right — it was the fix for a sandboxed agent escaping a listener-scoped
// profile by dialling the loopback port — but it means a key minted outside the
// run is simply not a run, and no amount of daemon-side logic can make it one.
// Neither sandbox confines the network, so the daemon cannot tell that the
// caller is inside a run when the caller does not say so.
//
// Which leaves one place to fix it: the key must not be readable from inside.
//
// WHAT THIS COSTS. These are the harness's own settings files, not credential
// stores, so masking one means a harness started inside `akasha run` sees its
// defaults rather than the user's configuration. That is a real cost and it is
// the right trade: the alternative is a run whose entire capability profile is
// bypassable by reading one file. A scrubbed copy bound over the original would
// keep both, and is the obvious improvement — but bwrap can bind a replacement
// and seatbelt cannot, so it would fix Linux and leave macOS, the primary
// platform for this tool, exactly as it is. A partial fix on a bypass is worse
// than an honest one.
//
// THIS LIST MUST NOT DRIFT from envTargetFor() in internal/setup/agentenv.go,
// which is the code that decides where the key is written. A test in that
// package asserts they agree, because a harness added there and forgotten here
// silently reopens the bypass.

// agentKeyTarget is one settings file that setup injects the agent key into.
// An empty goos means every platform.
type agentKeyTarget struct {
	goos string
	path string
}

// AgentKeyFiles lists the files that carry AKASHA_AGENT_KEY, for a given home
// directory. Exported so setup's drift test can compare it against the table it
// actually writes to.
func AgentKeyFiles(home string) []agentKeyTarget {
	if home == "" {
		return nil
	}
	at := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }
	return []agentKeyTarget{
		// Claude Code applies settings "env" to every session it starts,
		// including each Bash tool call — the strongest harness hook there is,
		// and therefore the most valuable file to read.
		{"", at(".claude", "settings.json")},

		// VS Code family: terminal.integrated.env.*, where Copilot and Cursor
		// agent shells run.
		{"linux", at(".config", "Code", "User", "settings.json")},
		{"linux", at(".config", "Code - Insiders", "User", "settings.json")},
		{"linux", at(".config", "Cursor", "User", "settings.json")},
		{"darwin", at("Library", "Application Support", "Code", "User", "settings.json")},
		{"darwin", at("Library", "Application Support", "Code - Insiders", "User", "settings.json")},
		{"darwin", at("Library", "Application Support", "Cursor", "User", "settings.json")},
	}
}

// AgentKeyPathsFor returns just the paths that apply to one platform.
func AgentKeyPathsFor(home, goos string) []string {
	var out []string
	for _, t := range AgentKeyFiles(home) {
		if t.goos == "" || t.goos == goos {
			out = append(out, t.path)
		}
	}
	return out
}
