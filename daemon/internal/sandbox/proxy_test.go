package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The proxy mode is the IP deny plus one loopback door. The macOS profile is
// generated text, so the door's spelling is asserted; Linux needs no rule and
// must not grow one by accident.
func TestProxyPortRendersPerPlatform(t *testing.T) {
	spec := Spec{DenyNetwork: true, ProxyPort: 48731}.AllowSocketPath("/tmp/akasha-run/egress.sock")

	darwin, err := DescribeFor("darwin", spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(deny network-outbound (remote ip "*:*"))`,
		"(deny network-inbound)",
		`(allow network-outbound (remote tcp "localhost:48731"))`,
		`(allow network-inbound (local tcp "localhost:48731"))`,
		`(allow network-outbound (literal "/tmp/akasha-run/egress.sock"))`,
	} {
		if !strings.Contains(darwin, want) {
			t.Errorf("darwin profile is missing %q:\n%s", want, darwin)
		}
	}
	// The allow must come AFTER the deny it punches through; SBPL is
	// last-match-wins.
	if strings.Index(darwin, `(remote ip "*:*")`) > strings.Index(darwin, `localhost:48731`) {
		t.Error("the port allow is rendered before the IP deny, so the deny wins")
	}

	linux, err := DescribeFor("linux", spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(linux, "--unshare-net") {
		t.Errorf("linux lost the namespace:\n%s", linux)
	}
	if strings.Contains(linux, "48731") {
		t.Errorf("linux rendered a port rule it has no mechanism for:\n%s", linux)
	}

	// `none` must not carry a port, and a port must not appear without the
	// deny — see Validate.
	if out, _ := DescribeFor("darwin", Spec{DenyNetwork: true}); strings.Contains(out, "localhost:") {
		t.Errorf("--network none rendered a loopback door:\n%s", out)
	}
	if _, err := DescribeFor("darwin", Spec{ProxyPort: 48731}); err == nil {
		t.Error("a ProxyPort without DenyNetwork validated")
	}
	if _, err := DescribeFor("darwin", Spec{DenyNetwork: true, ProxyPort: 70000}); err == nil {
		t.Error("an impossible port validated")
	}
}

// The self-test must carry the relay port, so an unusable one is found before
// the agent's first request rather than by it.
func TestSelfTestProbesTheProxyPort(t *testing.T) {
	spec := Spec{DenyNetwork: true, ProxyPort: 48731}
	plan, _ := planFor(spec)
	p := planProbe(spec, plan)
	p.ProxyPort = spec.ProxyPort // SelfTest sets this after planProbe; mirror it
	if p.ProxyPort != 48731 {
		t.Fatal("probe plan lost the proxy port")
	}
	if planProbe(Spec{DenyNetwork: true}, Plan{}).ProxyPort != 0 {
		t.Fatal("a run without a proxy got a port probe")
	}
}

// TestEnforceProxyPortIsTheOnlyIPDoor runs the profile for real: inside it, a
// listener on the proxy port can be bound and reached, and a port the parent
// is listening on outside cannot. On Linux the namespace makes the second
// claim; on macOS it is the rule this test exists to keep honest.
//
// The child is this test binary re-executed with an environment flag (the
// helper-process pattern), so the check runs in Go on both platforms with no
// dependency on what tools the sandbox happens to see.
func TestEnforceProxyPortIsTheOnlyIPDoor(t *testing.T) {
	requireSandbox(t)

	outside, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer outside.Close()
	go func() {
		for {
			c, err := outside.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Seatbelt refuses roughly one ephemeral port in thirty for a given
	// profile, deterministically per port (measured: the same port fails on
	// every retry while a fixed known-good port never does). The supervisor
	// handles that by proving the port in the self-test and choosing another;
	// this test does the same, and asserts the part that must hold on every
	// port: nothing outside is reachable.
	var out []byte
	for attempt := 0; attempt < 5; attempt++ {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		probe.Close()

		spec := Spec{DenyNetwork: true, ProxyPort: port}
		cmd := exec.Command(self, "-test.run=TestHelperProxyDoor$")
		cmd.Env = append(os.Environ(),
			"AKASHA_TEST_PROXY_DOOR=1",
			fmt.Sprintf("AKASHA_TEST_PROXY_PORT=%d", port),
			"AKASHA_TEST_OUTSIDE="+outside.Addr().String())
		if err := Wrap(spec, cmd); err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "outside: blocked") {
			t.Fatalf("the outside listener was reachable on port %d:\n%s", port, out)
		}
		if strings.Contains(string(out), "door-roundtrip: ok") {
			break
		}
		t.Logf("port %d refused by the profile, trying another:\n%s", port, out)
	}
	for _, want := range []string{"door-listen: ok", "door-roundtrip: ok", "outside: blocked"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in helper output after retries:\n%s", want, out)
		}
	}
}

// TestHelperProxyDoor is the inside half; it only does anything when re-executed
// by the test above.
func TestHelperProxyDoor(t *testing.T) {
	if os.Getenv("AKASHA_TEST_PROXY_DOOR") != "1" {
		t.Skip("helper process")
	}
	port := os.Getenv("AKASHA_TEST_PROXY_PORT")
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		fmt.Printf("door-listen: FAILED %v\n", err)
		os.Exit(0)
	}
	fmt.Println("door-listen: ok")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("RELAY-OK"))
		c.Close()
	}()
	c, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		fmt.Printf("door-roundtrip: FAILED %v\n", err)
	} else {
		buf := make([]byte, 8)
		n, _ := c.Read(buf)
		c.Close()
		if string(buf[:n]) == "RELAY-OK" {
			fmt.Println("door-roundtrip: ok")
		} else {
			fmt.Printf("door-roundtrip: FAILED got %q\n", buf[:n])
		}
	}
	if c, err := net.Dial("tcp", os.Getenv("AKASHA_TEST_OUTSIDE")); err == nil {
		c.Close()
		fmt.Println("outside: REACHABLE")
	} else {
		fmt.Println("outside: blocked")
	}
	os.Exit(0)
}
