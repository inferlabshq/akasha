package main

import (
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/template"
)

// exec routes on Brokerable(), not on "has an agent block". A template whose
// only ownership mechanism is a decoy has an agent block and no helper; the old
// test wired it to a credential helper that vends nothing, and the child's
// first credential call failed on a helper the user never asked for.
func TestExecRoutesDecoyOnlyProvidersToTheSessionPath(t *testing.T) {
	tpls := map[string]*template.Template{
		"decoyonly": {Name: "decoyonly",
			Agent: &template.AgentSpec{Own: []template.OwnDirective{{Mechanism: template.MechDecoy}}}},
		"brokered": {Name: "brokered",
			Deliver: []template.DeliverMode{{Mode: "helper"}},
			Agent:   &template.AgentSpec{Own: []template.OwnDirective{{Mechanism: template.MechCredentialProcess}}}},
	}
	lookup := func(p string) *template.Template { return tpls[p] }

	own, order, fallbacks, err := partitionAssumes([]string{"decoyonly:a", "brokered:b", "nothing:c"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := own["decoyonly"]; ok {
		t.Error("a decoy-only template was wired to a helper that vends nothing")
	}
	if _, ok := own["brokered"]; !ok || len(order) != 1 || order[0] != "brokered" {
		t.Errorf("a brokerable template must take the broker path: own=%v order=%v", own, order)
	}
	var fb []string
	for _, f := range fallbacks {
		fb = append(fb, f.provider+":"+f.profile)
	}
	if len(fb) != 2 || fb[0] != "decoyonly:a" || fb[1] != "nothing:c" {
		t.Errorf("fallbacks = %v, want [decoyonly:a nothing:c]", fb)
	}
}
