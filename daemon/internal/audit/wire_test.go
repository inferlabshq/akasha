package audit

import "testing"

// The wire values are frozen. This file is where a change to one becomes a
// deliberate act.
//
// Every other test in this package spells an action as its Go constant, so
// changing the literal behind ActionRetrieved from "RETRIEVED" to anything else
// compiles and passes all of them. The JSONL on disk is unversioned, the
// server tests match actions by exact string (waitForAudit), and anything
// outside this repo that reads the log matches by exact string too. So a
// silent change to a literal rewrites the meaning of every line already
// written. Adding a value is fine and is done here; changing one is not.
func TestActionWireValuesAreFrozen(t *testing.T) {
	frozen := map[Action]string{
		ActionVaulted:       "VAULTED",
		ActionRetrieved:     "RETRIEVED",
		ActionInspected:     "INSPECTED",
		ActionDenied:        "DENIED",
		ActionGranted:       "GRANTED",
		ActionDescribed:     "DESCRIBED",
		ActionUnbound:       "UNBOUND",
		ActionPolicyLoaded:  "POLICY_LOADED",
		ActionPolicyChanged: "POLICY_CHANGED",
		ActionPolicyMissing: "POLICY_MISSING",
		ActionRunBegin:      "RUN_BEGIN",
		ActionRunEnd:        "RUN_END",
	}
	for c, want := range frozen {
		if string(c) != want {
			t.Errorf("audit action %q is written to disk as %q -- changing a wire value rewrites the meaning of every line already logged", want, string(c))
		}
	}
}
