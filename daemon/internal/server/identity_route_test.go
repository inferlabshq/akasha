package server_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// ─── Identity-gate route coverage ───────────────────────────────────────────
//
// isHuman is the daemon's second access control and the one policy cannot
// express: a rule decides what a NAMED caller may do, and this decides whether
// the caller is the person at the keyboard at all. It is open-coded at
// seventeen call sites across three files, and until this file nothing asserted
// that any of them existed.
//
// That absence is the shape both escrow bugs had. Neither was a wrong rule;
// both were a door that did not ask. The first: the label test was
// case-sensitive while the vault resolves prefixes with SQL LIKE, so `ESCROW:`
// walked past a guard the database still matched. The second: widening that
// label test left the two call sites comparing a PROVIDER literal, so
// `/resolve?provider=ESCROW` kept listing every escrowed path through a door
// that had never asked the question at all. Both times a test existed and
// covered one door.
//
// The POLICY gate already has the guard that turns that omission into a build
// failure — TestDenyAllPolicyCoversEveryRoute walks the routes parsed out of
// server.go and makes the author of a new endpoint classify it. This is the
// same mechanism for the gate with more call sites and the worse history: every
// registered route is humanOnly, identityNarrowed or identityBlind, each with a
// reason and a request that MEASURES the claim rather than restating it.
//
// Nothing here re-tests the escrow rules themselves (escrow_gate_test.go and
// agent_surface_test.go do that, per door). What this adds is the property no
// per-door test can have: a door that nobody thought about is a failure.

type identityClass int

const (
	// humanOnly: the gate SHUTS the door. An agent-keyed request is refused
	// whatever it asks for; the same request as the local CLI is not.
	humanOnly identityClass = iota
	// identityNarrowed: the door stays open to agents and the gate removes one
	// named thing from what they may do through it. Both halves are asserted,
	// because a narrowing that has quietly become a closure passes every "the
	// agent was refused" check on its own.
	identityNarrowed
	// identityBlind: no isHuman branch is on this route's path. Whatever else
	// gates it — policy, run ownership, nothing — being the human or an agent
	// does not change the answer, and the reason has to say what does.
	identityBlind
)

// probe is one request, sent as both identities. Requests are built per test
// rather than declared as data because most of them have to address a real
// token, label or run that only exists once the env is up.
type probe struct {
	method string
	path   string
	body   interface{} // nil for a GET
}

type identityRule struct {
	class identityClass
	why   string
	// request drives humanOnly and identityBlind: the harness sends the SAME
	// request as both identities, because the property being asserted is the
	// difference between them.
	request func(t *testing.T, e *identityEnv) probe
	// narrowed drives identityNarrowed, where the refused case and the case
	// that must stay open are different requests.
	narrowed func(t *testing.T, e *identityEnv)
}

// identityGate is the table. Adding `s.mux.HandleFunc("/new", …)` fails
// TestEveryRouteClassifiesItsIdentityGate until its author decides which line
// this route belongs on and writes the request that proves it.
var identityGate = map[string]identityRule{

	// ── humanOnly ────────────────────────────────────────────────────────────

	"/vault/purge": {
		class: humanOnly,
		why: "deleting entries is the human's, and an agent had a primitive the person at the " +
			"keyboard does not even have a command for",
		request: func(t *testing.T, e *identityEnv) probe {
			return probe{"POST", "/vault/purge", map[string]string{}}
		},
	},
	"/credential/sources": {
		class: humanOnly,
		why: "absolute paths into someone's home directory — a map of where their secrets live, " +
			"and the sandbox that consumes it is built by the launcher, which runs as the person",
		request: func(t *testing.T, e *identityEnv) probe {
			return probe{"GET", "/credential/sources", nil}
		},
	},
	"/run/begin": {
		class: humanOnly,
		why: "a run mints a fresh policy identity, so an agent that could start one would launder " +
			"its own scope into rules written for a name it chose",
		request: func(t *testing.T, e *identityEnv) probe {
			// run_dir is deliberately invalid. The gate runs before the body is
			// even decoded, so the human's 400 still proves they passed it —
			// and a valid begin would leave a live listener and two goroutines
			// behind for the sake of one status code.
			return probe{"POST", "/run/begin", map[string]interface{}{"name": "probe", "run_dir": ""}}
		},
	},
	"/shutdown": {
		class: humanOnly,
		why: "\"deny service to the thing that audits me\" is a capability worth withholding even " +
			"under the same-uid ceiling",
		request: func(t *testing.T, e *identityEnv) probe {
			// The human's control is a 501: an httptest server has no stop path
			// wired, which is the answer handleShutdown gives once identity has
			// been established.
			return probe{"POST", "/shutdown", map[string]string{}}
		},
	},

	// ── identityNarrowed ─────────────────────────────────────────────────────

	"/store": {
		class: identityNarrowed,
		why: "an agent may not vault a value it invented or a file-sized one; the human pushes " +
			"whatever is actually in their config through here, unreal dev keys included",
		narrowed: func(t *testing.T, e *identityEnv) {
			refusedOnlyForAgents(t, e, "/store of an invented value", probe{"POST", "/store",
				map[string]string{"content": "my_secret_value", "category": "APIKey", "risk": "high"},
			}, http.StatusBadRequest)
			// The size cap is spelled twice on this path — once before the value
			// checks for the sake of the message, once inside checkStoredValue —
			// so this pins the DOOR's answer and not either branch. `akasha
			// protect` pushes whole credential files through here; an agent has
			// no such need.
			refusedOnlyForAgents(t, e, "/store of a file-sized value", probe{"POST", "/store",
				map[string]string{
					"content":  strings.Repeat("x", maxAgentBytes+1),
					"category": "EscrowedFile", "risk": "high",
				},
			}, http.StatusBadRequest)
			reachedByAgents(t, e, "/store of a secret an agent was given", probe{"POST", "/store",
				map[string]string{"content": ordinaryValue, "category": "UserSecret", "risk": "high"},
			}, http.StatusOK)
		},
	},
	"/retrieve": {
		class: identityNarrowed,
		why: "an escrowed entry's value IS the plaintext its owner took off disk, so it has no " +
			"brokered form and no agent reads it; every other token is ordinary retrieval",
		narrowed: func(t *testing.T, e *identityEnv) {
			_, _, escrowTok := protectFixture(t, e.vlt)
			refusedOnlyForAgents(t, e, "/retrieve of an escrowed file", probe{"POST", "/retrieve",
				map[string]string{"token": escrowTok, "requesting_tool": "read_file"},
			}, http.StatusForbidden)
			reachedByAgents(t, e, "/retrieve of an ordinary secret", probe{"POST", "/retrieve",
				map[string]string{
					"token": storeOrdinary(t, e), "agent_id": "claude", "requesting_tool": "lookup",
				},
			}, http.StatusOK)
		},
	},
	"/label/set": {
		class: identityNarrowed,
		why: "an agent may ADD a name and may not take one over — refusing both would push callers " +
			"toward reusing a name that already exists, which is the thing being stopped",
		narrowed: func(t *testing.T, e *identityEnv) {
			_, escrowLabel, _ := protectFixture(t, e.vlt)
			agentTok := storeOrdinary(t, e)
			bindLabel(t, e, "env:shared")

			refusedOnlyForAgents(t, e, "/label/set re-pointing an existing name", probe{"POST", "/label/set",
				map[string]string{"name": "env:shared", "token": agentTok},
			}, http.StatusForbidden)
			refusedOnlyForAgents(t, e, "/label/set on an escrow name", probe{"POST", "/label/set",
				map[string]string{"name": escrowLabel, "token": agentTok},
			}, http.StatusForbidden)
			reachedByAgents(t, e, "/label/set creating a name of the agent's own", probe{"POST", "/label/set",
				map[string]string{"name": "env:agentown", "token": agentTok},
			}, http.StatusOK)
		},
	},
	"/credential/retrieve": {
		class: identityNarrowed,
		why:   "this door returns the decrypted value, so the escrow namespace is closed to agents and nothing else is",
		narrowed: func(t *testing.T, e *identityEnv) {
			_, escrowLabel, _ := protectFixture(t, e.vlt)
			bindLabel(t, e, "env:readable")

			refusedOnlyForAgents(t, e, "/credential/retrieve of an escrowed file", probe{"GET",
				"/credential/retrieve?name=" + url.QueryEscape(escrowLabel), nil,
			}, http.StatusForbidden)
			reachedByAgents(t, e, "/credential/retrieve of an ordinary credential", probe{"GET",
				"/credential/retrieve?name=env:readable", nil,
			}, http.StatusOK)
		},
	},
	"/label/list": {
		class: identityNarrowed,
		why: "escrow labels are the absolute paths of the files their owner protected — a target " +
			"list — so they are FILTERED out for an agent rather than the listing being refused",
		narrowed: func(t *testing.T, e *identityEnv) {
			_, escrowLabel, _ := protectFixture(t, e.vlt)
			bindLabel(t, e, "env:ordinary")
			list := probe{"GET", "/label/list", nil}

			if code, body := e.asHuman(t, list); code != http.StatusOK || !strings.Contains(body, escrowLabel) {
				t.Fatalf("the owner must see their own escrow labels: %d %s", code, body)
			}
			code, body := e.asAgent(t, list)
			if code != http.StatusOK {
				t.Fatalf("an agent listing labels got %d — a bare `list` has to keep working from "+
					"inside an agent session, or vault_status stops answering\n%s", code, body)
			}
			if strings.Contains(body, escrowLabel) || strings.Contains(body, escrow.LabelPrefix) {
				t.Errorf("the escrow inventory was listed to an agent:\n%s", body)
			}
			// The filter has to remove the escrow names and nothing else.
			// Returning an empty list satisfies the check above while breaking
			// the endpoint.
			if !strings.Contains(body, "env:ordinary") {
				t.Errorf("the filter took the agent's ordinary labels with it:\n%s", body)
			}
		},
	},
	"/label/delete": {
		class: identityNarrowed,
		why: "removing an existing name is DELETE plus CREATE — a re-point spelled in two commands — " +
			"so it is refused for the same reason /label/set's rebind is, and a name that does not " +
			"exist is not refused at all",
		narrowed: func(t *testing.T, e *identityEnv) {
			_, escrowLabel, _ := protectFixture(t, e.vlt)
			bindLabel(t, e, "env:shared")

			refusedOnlyForAgents(t, e, "/label/delete of an escrow name", probe{"POST", "/label/delete",
				map[string]interface{}{"name": escrowLabel},
			}, http.StatusForbidden)
			refusedOnlyForAgents(t, e, "/label/delete of an existing name", probe{"POST", "/label/delete",
				map[string]interface{}{"name": "env:shared"},
			}, http.StatusForbidden)
			// A 404 rather than a 403: the refusal keys on there being
			// something to take, not on the caller being an agent.
			reachedByAgents(t, e, "/label/delete of a name that does not exist", probe{"POST", "/label/delete",
				map[string]interface{}{"name": "env:nosuchname"},
			}, http.StatusNotFound)
		},
	},
	"/profile/save": {
		class: identityNarrowed,
		why: "a profile row is a second binding of provider:profile → token, resolved by the same " +
			"tooling paths as a label, so it inherits the bind gate's refusal to re-point",
		narrowed: func(t *testing.T, e *identityEnv) {
			seedAWS(t, e.vlt, "default", testAccount)
			agentTok := storeOrdinary(t, e)

			refusedOnlyForAgents(t, e, "/profile/save re-pointing an existing name", probe{"POST", "/profile/save",
				map[string]interface{}{"provider": "aws", "profile": "default", "token": agentTok},
			}, http.StatusForbidden)
			reachedByAgents(t, e, "/profile/save under a name of the agent's own", probe{"POST", "/profile/save",
				map[string]interface{}{"provider": "env", "profile": "agentown", "token": agentTok},
			}, http.StatusOK)
		},
	},
	"/put": {
		class: identityNarrowed,
		why: "/put ends in SetLabel, so it is both doors at once: an agent's value is judged (a " +
			"decoy here becomes what the NAME resolves to) and an agent's re-point is refused",
		narrowed: func(t *testing.T, e *identityEnv) {
			bindLabel(t, e, "env:shared")

			refusedOnlyForAgents(t, e, "/put of an invented aws key", probe{"POST", "/put",
				map[string]interface{}{"label": "aws:agentown", "fields": map[string]string{
					"access_key_id": "not-a-key", "secret_access_key": "also-not-a-key",
				}},
			}, http.StatusBadRequest)
			refusedOnlyForAgents(t, e, "/put re-pointing an existing name", probe{"POST", "/put",
				map[string]interface{}{"label": "env:shared", "fields": map[string]string{
					"api_key": ordinaryValue,
				}},
			}, http.StatusForbidden)
			reachedByAgents(t, e, "/put under a name of the agent's own", probe{"POST", "/put",
				map[string]interface{}{"label": "env:agentown", "fields": map[string]string{
					"api_key": ordinaryValue,
				}},
			}, http.StatusOK)
		},
	},
	"/assume": {
		class: identityNarrowed,
		why: "a provider whose delivery materializes a raw secret would land the value in the " +
			"agent's session environment; a file-delivered one hands back a path, which is what " +
			"assume is for",
		narrowed: func(t *testing.T, e *identityEnv) { sessionDoorNarrowed(t, e, "/assume") },
	},
	"/session": {
		class: identityNarrowed,
		why: "alias of /assume served by the same handler; listed so the mux scan cannot let an " +
			"alias drift from the door it duplicates",
		narrowed: func(t *testing.T, e *identityEnv) { sessionDoorNarrowed(t, e, "/session") },
	},
	"/resolve": {
		class: identityNarrowed,
		why: "the broker is the path the product is built on and runs INSIDE agent sessions, so " +
			"only escrow — which has no per-operation use, just raw bytes — is closed here",
		narrowed: func(t *testing.T, e *identityEnv) {
			seedAWS(t, e.vlt, "default", testAccount)
			protectFixture(t, e.vlt)

			refusedOnlyForAgents(t, e, "/resolve of the escrow provider", probe{"GET",
				"/resolve?provider=escrow&instance=default", nil,
			}, http.StatusForbidden)
			reachedByAgents(t, e, "/resolve of a brokered provider", probe{"GET",
				"/resolve?provider=aws&instance=default", nil,
			}, http.StatusOK)
		},
	},

	// ── identityBlind ────────────────────────────────────────────────────────

	"/wrap": {
		class: identityBlind,
		why:   "redacts secrets INTO the vault and hands nothing back, so there is no access for identity to decide",
		request: func(t *testing.T, e *identityEnv) probe {
			return probe{"POST", "/wrap", map[string]string{
				"agent_id": "probe", "tool_name": "lookup", "content": "SSN 429-21-0001",
			}}
		},
	},
	"/grant": {
		class: identityBlind,
		why: "delegation between agents is exactly what an agent does here; who may delegate what " +
			"is a policy question, and the gate on redemption is /retrieve's",
		request: func(t *testing.T, e *identityEnv) probe {
			return probe{"POST", "/grant", map[string]interface{}{
				"token": storeOrdinary(t, e), "grantor_agent": "a",
				"grantee_agent": "b", "allowed_tool": "lookup",
			}}
		},
	},
	"/inspect": {
		class: identityBlind,
		why:   "metadata about an entry, never its value; a min_risk rule is the control that reaches it",
		request: func(t *testing.T, e *identityEnv) probe {
			return probe{"GET", "/inspect?token=" + storeOrdinary(t, e), nil}
		},
	},
	"/identity": {
		class: identityBlind,
		why: "DESCRIBE hands back non-secret facts and never decrypts the secret half, so an agent " +
			"asking who a credential belongs to is the case it exists for",
		request: func(t *testing.T, e *identityEnv) probe {
			seedAWS(t, e.vlt, "default", testAccount)
			return probe{"GET", "/identity?provider=aws&profile=default", nil}
		},
	},
	"/run/attach": {
		class: identityBlind,
		why: "gated by run OWNERSHIP rather than by identity (ownsRun / foreignRunRefusal). Read the " +
			"class narrowly: this says isHuman decides nothing here, NOT that an agent may attach to " +
			"your run. It cannot — /run/begin is human-only, so every run's owner is the CLI and an " +
			"agent fails the ownership check on any run that exists",
		request: func(t *testing.T, e *identityEnv) probe {
			// A run nobody owns, deliberately. Ownership IS a difference between
			// these two callers, and addressing a real run would answer with it
			// instead of with the question this route is being asked.
			return probe{"GET", "/run/attach?run_id=no-such-run", nil}
		},
	},
	"/run/end": {
		class: identityBlind,
		why: "gated by run OWNERSHIP rather than by identity (ownsRun): ending a run revokes its " +
			"key, so an unscoped /run/end would be a kill switch on anyone else's run. Same narrow " +
			"reading as /run/attach — isHuman decides nothing here, and an agent still cannot end a " +
			"run, because it cannot own one",
		request: func(t *testing.T, e *identityEnv) probe {
			// Unowned for the same reason /run/attach's probe is.
			return probe{"POST", "/run/end", map[string]string{"run_id": "no-such-run"}}
		},
	},
	"/health": {
		class: identityBlind,
		why: "the counts beyond liveness are gated on presenting ANY verified key, because loopback " +
			"reaches past the uid boundary the unix socket enforces — a distinction about keys, not about who holds one",
		request: func(t *testing.T, e *identityEnv) probe {
			return probe{"GET", "/health", nil}
		},
	},
}

// ─── The harness ────────────────────────────────────────────────────────────

// Every route the mux registers says what the identity gate does to it, and the
// answer is measured.
func TestEveryRouteClassifiesItsIdentityGate(t *testing.T) {
	registered := registeredRoutes(t)
	known := map[string]bool{}
	for _, route := range registered {
		known[route] = true
	}
	for _, route := range sortedKeys(identityGate) {
		if !known[route] {
			t.Errorf("identityGate classifies %s, which the mux no longer registers — a stale entry "+
				"here is a claim about a door that is not there", route)
		}
	}

	for _, route := range registered {
		rule, ok := identityGate[route]
		if !ok {
			t.Errorf("route %s is registered and nothing here says what the identity gate does to "+
				"it: classify it humanOnly, identityNarrowed or identityBlind, give the reason, and "+
				"write the request that shows it", route)
			continue
		}
		if rule.why == "" {
			t.Errorf("%s is classified with no reason", route)
			continue
		}
		t.Run(subtestName(route), func(t *testing.T) {
			e := newIdentityEnv(t)
			switch rule.class {
			case humanOnly:
				if rule.request == nil {
					t.Fatalf("%s is humanOnly with no request — the class is a claim, not a note", route)
				}
				p := rule.request(t, e)
				if code, body := e.asAgent(t, p); code != http.StatusForbidden {
					t.Errorf("%s as an agent: got %d, want 403 — this route is human-only and nothing "+
						"on its path asks who is calling\n%s", route, code, strings.TrimSpace(body))
				}
				if code, body := e.asHuman(t, p); code == http.StatusForbidden {
					t.Errorf("%s as the local CLI: refused with 403 as well, so the refusal is not "+
						"about identity — the owner is locked out of their own daemon\n%s",
						route, strings.TrimSpace(body))
				}

			case identityNarrowed:
				if rule.narrowed == nil {
					t.Fatalf("%s is identityNarrowed with no assertion — say which request is refused "+
						"for an agent and which one must still get through", route)
				}
				rule.narrowed(t, e)

			case identityBlind:
				if rule.request == nil {
					t.Fatalf("%s is identityBlind with no request", route)
				}
				p := rule.request(t, e)
				agentCode, agentBody := e.asAgent(t, p)
				humanCode, humanBody := e.asHuman(t, p)
				// A probe both identities fail to parse proves nothing about
				// identity, and is how this check would rot into a tautology.
				if humanCode == http.StatusBadRequest || agentCode == http.StatusBadRequest {
					t.Fatalf("%s: the probe is malformed (cli %d, agent %d) — a 400 either way says "+
						"nothing about who was asking\ncli: %s\nagent: %s", route, humanCode, agentCode,
						strings.TrimSpace(humanBody), strings.TrimSpace(agentBody))
				}
				if agentCode != humanCode {
					t.Errorf("%s answers %d to the local CLI and %d to an agent, so identity DOES "+
						"decide something here: reclassify it as humanOnly or identityNarrowed and say "+
						"what the branch protects\ncli: %s\nagent: %s", route, humanCode, agentCode,
						strings.TrimSpace(humanBody), strings.TrimSpace(agentBody))
				}
			}
		})
	}
}

// refusedOnlyForAgents is the shape every identity gate takes: one request,
// refused for an agent and not for the owner.
//
// Both halves, because either alone is a bug. A refusal that also catches the
// human is how `akasha protect` turns a protected credential into a lost one —
// the failure a `deny` policy rule produces on a headless machine, and the
// reason this boundary is drawn by identity in the daemon rather than by a rule
// in a file the user can edit.
func refusedOnlyForAgents(t *testing.T, e *identityEnv, what string, p probe, want int) {
	t.Helper()
	if code, body := e.asAgent(t, p); code != want {
		t.Errorf("%s as an agent: got %d, want %d — nothing on this path asks who is calling\n%s",
			what, code, want, strings.TrimSpace(body))
	}
	if code, body := e.asHuman(t, p); code == want {
		t.Errorf("%s as the local CLI: refused with %d too, so this refusal is not about identity — "+
			"either the classification is wrong or the owner has been shut out of their own vault\n%s",
			what, code, strings.TrimSpace(body))
	}
}

// reachedByAgents is the other half of a narrowing, and the half that is easy to
// lose: a gate that has quietly become a blanket refusal satisfies every "the
// agent was refused" assertion on its own. Each narrowed route therefore also
// names a request an agent must still get through.
func reachedByAgents(t *testing.T, e *identityEnv, what string, p probe, want int) {
	t.Helper()
	code, body := e.asAgent(t, p)
	if code == http.StatusForbidden && want != http.StatusForbidden {
		t.Errorf("%s as an agent: 403. This door is not narrowed for agents, it is shut — and an "+
			"agent that cannot do its ordinary work here has no route left but to ask the human to "+
			"switch the protection off\n%s", what, strings.TrimSpace(body))
		return
	}
	if code != want {
		t.Errorf("%s as an agent: got %d, want %d\n%s", what, code, want, strings.TrimSpace(body))
	}
}

// ─── Where the gate is spelled ──────────────────────────────────────────────

// gateSite records what one function that decides on isHuman is deciding.
type gateSite struct {
	// routes whose answer this function's identity branch changes. Empty means
	// the function reaches isHuman without closing any door, and then why has to
	// say what it does instead — an entry that also stops the call-graph walk
	// below, so it is a claim with teeth rather than a note.
	routes []string
	why    string
}

// identityGateSites names every function that decides something on isHuman, and
// the routes its decision reaches.
//
// The table above measures behaviour through the mux; this one ties that
// behaviour back to the code, in both directions. Without it a route classified
// identityBlind can silently grow a branch on a case no probe happens to
// address, and a route classified as gated can lose its branch while a probe
// that 403s for some other reason keeps the table green.
var identityGateSites = map[string]gateSite{
	"handleStore":              {routes: []string{"/store"}},
	"handleRetrieve":           {routes: []string{"/retrieve"}},
	"handleCredentialRetrieve": {routes: []string{"/credential/retrieve"}},
	"handleLabelList":          {routes: []string{"/label/list"}},
	"handleLabelDelete":        {routes: []string{"/label/delete"}},
	"handlePut":                {routes: []string{"/put"}},
	"handleAssume":             {routes: []string{"/assume", "/session"}},
	"handleResolve":            {routes: []string{"/resolve"}},
	"handleVaultPurge":         {routes: []string{"/vault/purge"}},
	"handleCredentialSources":  {routes: []string{"/credential/sources"}},
	"handleRunBegin":           {routes: []string{"/run/begin"}},
	"handleShutdown":           {routes: []string{"/shutdown"}},

	// The bind gate is shared, and neither of these handlers mentions isHuman.
	// They are found because the scan follows calls: hanging a guard on one of
	// two doors onto the same SetLabel has already happened here, and a scan
	// that only read each handler's own body would let the next endpoint that
	// calls authorizeBind be classified identityBlind and believed.
	"authorizeBind":     {routes: []string{"/label/set", "/put", "/profile/save"}},
	"handleLabelSet":    {routes: []string{"/label/set"}},
	"handleProfileSave": {routes: []string{"/profile/save"}},

	// Not a gate, and the entry that keeps the walk from swallowing the daemon.
	// withRun records caller.human as a policy FACT — a rule may key on it and
	// nothing is refused here — but EVERY caller construction runs it, so
	// counting it would mark all 21 routes identity-gated and leave this test
	// asserting nothing at all.
	"withRun": {why: "records caller.human for the policy request; it closes no door"},
}

// The classification and the code agree, in both directions.
func TestIdentityGateSitesMatchTheClassification(t *testing.T) {
	notAGate := map[string]bool{}
	for fn, site := range identityGateSites {
		if len(site.routes) == 0 {
			notAGate[fn] = true
		}
	}
	found := isHumanReachers(t, notAGate)
	if len(found) == 0 {
		t.Fatal("found no isHuman call sites in this package — this test's source scan has rotted, " +
			"which would silently make it assert nothing")
	}
	registered := map[string]bool{}
	for _, route := range registeredRoutes(t) {
		registered[route] = true
	}

	for _, fn := range sortedKeys(found) {
		site, ok := identityGateSites[fn]
		if !ok {
			t.Errorf("%s decides on isHuman and is not in identityGateSites: name the routes whose "+
				"answer it changes — or, if it closes no door, say what it does instead", fn)
			continue
		}
		if len(site.routes) == 0 && site.why == "" {
			t.Errorf("%s is listed as closing no door, with no reason", fn)
		}
		for _, route := range site.routes {
			if !registered[route] {
				t.Errorf("identityGateSites says %s gates %s, which the mux does not register", fn, route)
			}
		}
	}
	for _, fn := range sortedKeys(identityGateSites) {
		if !found[fn] {
			t.Errorf("identityGateSites lists %s, which no longer reaches isHuman: either the gate was "+
				"removed — and the routes it covered are now open to any key-holding agent — or this "+
				"entry is stale", fn)
		}
	}

	gatedInCode := map[string]bool{}
	for fn, site := range identityGateSites {
		if !found[fn] {
			continue
		}
		for _, route := range site.routes {
			gatedInCode[route] = true
		}
	}
	for _, route := range sortedKeys(identityGate) {
		switch identityGate[route].class {
		case identityBlind:
			if gatedInCode[route] {
				t.Errorf("%s is classified identityBlind, but an isHuman branch decides it. Whatever "+
					"that branch protects is now untested: reclassify the route and write the request "+
					"that shows the refusal", route)
			}
		default:
			if !gatedInCode[route] {
				t.Errorf("%s is classified as identity-gated, but no isHuman call site names it. If "+
					"the branch was removed the route is open to any key-holding agent; if it moved, "+
					"say where", route)
			}
		}
	}
}

// isHumanReachers returns every function in this package's non-test sources
// that decides something on isHuman: the ones that call it, plus the ones that
// reach one of those through a call.
//
// Read from the source for the same reason registeredRoutes is — a
// hand-maintained copy would go stale in exactly the case the test exists for —
// and followed one call deep because the gate is not always in the handler.
// /label/set and /profile/save never mention isHuman and are both gated, in the
// authorizeBind they share with /put.
//
// notAGate stops the propagation. A function listed there still appears in the
// result if it calls isHuman itself (so the entry cannot go stale unnoticed),
// but nothing inherits from it. That is what keeps withRun — which every caller
// construction runs, and which refuses nothing — from marking the whole daemon
// identity-gated.
func isHumanReachers(t *testing.T, notAGate map[string]bool) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	calls := map[string]map[string]bool{}
	reaches := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			caller := fn.Name.Name
			if calls[caller] == nil {
				calls[caller] = map[string]bool{}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				// Selector as well as bare ident, because the gate is reached
				// through methods: `s.authorizeBind(...)`.
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				if callee == "" {
					return true
				}
				if callee == "isHuman" {
					reaches[caller] = true
				}
				calls[caller][callee] = true
				return true
			})
		}
	}
	for changed := true; changed; {
		changed = false
		for caller, callees := range calls {
			if reaches[caller] || notAGate[caller] {
				continue
			}
			for callee := range callees {
				if reaches[callee] && !notAGate[callee] {
					reaches[caller] = true
					changed = true
					break
				}
			}
		}
	}
	return reaches
}

// ─── Fixtures ───────────────────────────────────────────────────────────────

// ordinaryValue is a secret that is not a placeholder and not the shape of any
// provider's credential, so a probe can exercise a door without the value
// checks having an opinion about it.
const ordinaryValue = "Zq4v9Lm2x8Kd"

type identityEnv struct {
	ts       *httptest.Server
	vlt      *vault.Vault
	agentKey string
}

func newIdentityEnv(t *testing.T) *identityEnv {
	t.Helper()
	// A credential materialized by /assume lands in $HOME/.akasha when nothing
	// better exists, and this suite must never write a working credential into
	// the developer's real home. XDG_RUNTIME_DIR is ahead of that fallback in
	// assume's candidate list, so pointing it at this test's directory keeps
	// the file where the test can clean it up.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	ts, vlt := newTestServer(t)
	// Trust is a different gate with its own tests. Establishing it up front
	// keeps an untrusted-template 403 from being mistaken for an identity one.
	trustBundle(t)
	_, key, err := vlt.CreateAgentKey("claude")
	if err != nil {
		t.Fatalf("create agent key: %v", err)
	}
	return &identityEnv{ts: ts, vlt: vlt, agentKey: key}
}

// send issues p under one identity. An empty key means the local human CLI: the
// test server's own client fills that in (see humanServer), which is the only
// way to authenticate as vault.IdentityCLI without minting a second key for it.
func (e *identityEnv) send(t *testing.T, p probe, key string) (int, string) {
	t.Helper()
	var body io.Reader
	if p.body != nil {
		b, err := json.Marshal(p.body)
		if err != nil {
			t.Fatalf("marshal %s body: %v", p.path, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(p.method, e.ts.URL+p.path, body)
	if err != nil {
		t.Fatalf("build %s %s: %v", p.method, p.path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Akasha-Key", key)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", p.method, p.path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *identityEnv) asAgent(t *testing.T, p probe) (int, string) {
	t.Helper()
	return e.send(t, p, e.agentKey)
}

func (e *identityEnv) asHuman(t *testing.T, p probe) (int, string) {
	t.Helper()
	return e.send(t, p, "")
}

// storeOrdinary vaults a secret that is nobody's escrowed file, so a probe can
// address a real entry without dragging the escrow gate into the answer.
func storeOrdinary(t *testing.T, e *identityEnv) string {
	t.Helper()
	tok, err := e.vlt.Store(ordinaryValue, "UserSecret", "high", "seeder", "seed", 0)
	if err != nil {
		t.Fatalf("vault a probe secret: %v", err)
	}
	return tok
}

// bindLabel gives name a credential of the human's, which is the precondition
// for every "an agent may not take over an existing name" probe.
func bindLabel(t *testing.T, e *identityEnv, name string) string {
	t.Helper()
	tok := storeOrdinary(t, e)
	if err := e.vlt.SetLabel(name, tok); err != nil {
		t.Fatalf("bind %s: %v", name, err)
	}
	return tok
}

// subtestName keeps a route readable as a -run pattern; '/' would otherwise
// nest each one under a subtest that does not exist.
func subtestName(route string) string {
	return strings.ReplaceAll(strings.TrimPrefix(route, "/"), "/", "_")
}

// sortedKeys keeps the failure list in a stable order. Both tables are maps, and
// a reviewer comparing two runs of a failing build should not have to diff a
// reordering as well.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sessionDoorNarrowed is the identity narrowing of the session door, shared by
// its two routes. One body, two paths: if the alias ever stops being the same
// door, the table entry that points here is what says so.
func sessionDoorNarrowed(t *testing.T, e *identityEnv, path string) {
	t.Helper()
	seedAWS(t, e.vlt, "default", testAccount)
	if code, body := e.asHuman(t, probe{"POST", "/put", map[string]interface{}{
		"label": "env:app", "fields": map[string]string{"API_KEY": ordinaryValue},
		"provider": "env", "profile": "app",
	}}); code != http.StatusOK {
		t.Fatalf("seeding env:app: %d %s", code, body)
	}
	refusedOnlyForAgents(t, e, path+" of a raw-secret provider", probe{"POST", path,
		map[string]string{"provider": "env", "profile": "app"},
	}, http.StatusForbidden)
	reachedByAgents(t, e, path+" of a file-delivered provider", probe{"POST", path,
		map[string]string{"provider": "aws", "profile": "default"},
	}, http.StatusOK)
}
