package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// recordingLabels stands up a daemon that answers /label/list with the given
// names, and points socketPath at it. The returned func is a no-op kept so the
// caller reads as a paired setup/teardown; cleanup is registered on t.
func recordingLabels(t *testing.T, names []string) func() {
	t.Helper()
	// Short path: a socket under the temp dir t.TempDir() hands out on macOS
	// exceeds the 104-byte sun_path limit, and a test that skips proves nothing.
	dir, err := os.MkdirTemp("/tmp", "aklabels")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	// A bare JSON array, matching handleLabelList. Answering the wrong shape
	// here would make the guard silently skip and the test pass for nothing.
	body, _ := json.Marshal(names)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			c.Read(buf)
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
				itoa(len(body)) + "\r\n\r\n"))
			c.Write(body)
			c.Close()
		}
	}()

	old := socketPath
	socketPath = ln.Addr().String()
	t.Cleanup(func() { socketPath = old; ln.Close() })
	return func() {}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
