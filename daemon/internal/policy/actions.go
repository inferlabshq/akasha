package policy

import "strings"

// Actions lists the policy verbs, in the order the docs present them. It is
// the one place the vocabulary is spelled out: the parser validates against
// it, the parse error is generated from it, and the docs table is checked
// against it -- so the three cannot drift, which they had (the error string
// at the old switch listed eight verbs; there were nine).
//
// Precedent: RiskLevels and CategoryLevels, for the same reason.
func Actions() []string {
	return []string{"retrieve", "broker", "session", "grant", "inspect", "describe", "list", "bind", "purge"}
}

// actionAliases maps a spelling still accepted on disk to the verb it means.
//
// This map is what keeps an upgrade from locking a machine out of its own
// credentials. The action switch used to be a hard list on BOTH parse paths,
// and an unknown action is a parse error, and a parse error denies
// everything. So the day `assume` became `session`, every installed
// policy.yaml that spelled the rule the way `policy init` had written it would
// have stopped parsing -- and the daemon would have refused every request
// until someone edited a file they had no reason to think was wrong.
//
// An alias is accepted for one release and reported by `policy validate`
// (see Deprecations). It is normalised on read, so nothing downstream of the
// parser ever sees the old spelling; the file on disk is never rewritten.
var actionAliases = map[string]string{
	"assume": "session",
}

// CanonicalAction resolves an action as written -- in a rule or a request --
// to the verb it means. ok is false for a value that is neither a verb nor an
// alias. Globs are deliberately not handled here: the parser never accepted a
// pattern in `action:`, and resolving one would widen what a rule can match.
func CanonicalAction(a string) (canonical string, ok bool) {
	if a == "" {
		return "", true
	}
	if c, isAlias := actionAliases[a]; isAlias {
		return c, true
	}
	for _, v := range Actions() {
		if v == a {
			return a, true
		}
	}
	return "", false
}

// actionsForError is the list as the parse error prints it.
func actionsForError() string {
	vs := Actions()
	return strings.Join(vs[:len(vs)-1], ", ") + " or " + vs[len(vs)-1]
}
