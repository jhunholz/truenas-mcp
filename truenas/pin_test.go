package truenas

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

type fakeResolver struct {
	addrs   []string
	err     error
	lookups atomic.Int32
}

func (r *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	r.lookups.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	out := make([]net.IPAddr, 0, len(r.addrs))
	for _, a := range r.addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

// pinnedClient talks to the fake as "example.com" (a name its certificate
// covers), with DNS answered by r and the pin set to pin.
func pinnedClient(t *testing.T, f *fakeTrueNAS, r Resolver, pin string) *Client {
	t.Helper()
	c, err := NewClientWithOptions(f.wsURL("example.com"), testAPIKey, f.trustingTLS(),
		Options{PinIP: net.ParseIP(pin), Resolver: r})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestPinHappyPath(t *testing.T) {
	f := newFakeTrueNAS(t, nil)
	c := pinnedClient(t, f, &fakeResolver{addrs: []string{"127.0.0.1"}}, "127.0.0.1")
	if _, err := c.Call("system.info"); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !f.sawKey() {
		t.Fatal("sanity: the key should reach the pinned fake")
	}
}

func TestPinRefusesWrongDNS(t *testing.T) {
	cases := map[string]*fakeResolver{
		"other address": {addrs: []string{"10.0.0.5"}},
		"mixed answer":  {addrs: []string{"127.0.0.1", "10.0.0.5"}},
		"extra AAAA":    {addrs: []string{"127.0.0.1", "::1"}},
		"empty answer":  {addrs: nil},
		"lookup error":  {err: errors.New("i/o timeout")},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeTrueNAS(t, nil)
			c := pinnedClient(t, f, r, "127.0.0.1")
			_, err := c.Call("system.info")
			if err == nil {
				t.Fatal("expected refusal")
			}
			if !strings.Contains(err.Error(), "refusing:") || !strings.Contains(err.Error(), "key not sent") {
				t.Errorf("error should be a pin refusal, got: %v", err)
			}
			if _, _, conns := f.snapshot(); conns != 0 {
				t.Errorf("connected %d times despite DNS refusal", conns)
			}
			if f.sawKey() {
				t.Error("API key reached the server")
			}
			if n := r.lookups.Load(); n != 1 {
				t.Errorf("lookups = %d, want 1 (refusal must not be retried)", n)
			}
		})
	}
}

func TestPinnedDialIgnoresHostname(t *testing.T) {
	f := newFakeTrueNAS(t, nil)
	port := f.Listener.Addr().(*net.TCPAddr).Port
	dial := pinnedDialContext(net.ParseIP("127.0.0.1"))
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("unresolvable.invalid", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("pinned dial: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().(*net.TCPAddr); !got.IP.Equal(net.ParseIP("127.0.0.1")) || got.Port != port {
		t.Errorf("dialed %v, want 127.0.0.1:%d", got, port)
	}
}

func TestPinPeerMismatchRefusesBeforeAuth(t *testing.T) {
	f := newFakeTrueNAS(t, nil)
	c := pinnedClient(t, f, &fakeResolver{addrs: []string{"127.0.0.1"}}, "127.0.0.1")
	c.peerAddr = func(*websocket.Conn) net.Addr {
		return &net.TCPAddr{IP: net.ParseIP("10.9.9.9"), Port: 443}
	}
	err := c.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "connected to 10.9.9.9") || !strings.Contains(err.Error(), "key not sent") {
		t.Fatalf("expected peer refusal, got: %v", err)
	}
	if frames, _, _ := f.snapshot(); len(frames) != 0 {
		t.Errorf("client sent %d frames after a peer mismatch", len(frames))
	}
}

func TestPinIgnoresProxyEnv(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	t.Setenv("HTTPS_PROXY", "http://"+proxy.Addr().String())
	t.Setenv("HTTP_PROXY", "http://"+proxy.Addr().String())

	f := newFakeTrueNAS(t, nil)
	c := pinnedClient(t, f, &fakeResolver{addrs: []string{"127.0.0.1"}}, "127.0.0.1")
	if _, err := c.Call("system.info"); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("proxy received %d connections; the pin must govern the destination", n)
	}
}

func TestPinRefusesInsecure(t *testing.T) {
	_, err := NewClientWithOptions("wss://example.com:443/api/current", testAPIKey,
		&tls.Config{InsecureSkipVerify: true}, Options{PinIP: net.ParseIP("127.0.0.1")})
	if err == nil || !strings.Contains(err.Error(), "--insecure") {
		t.Fatalf("expected --pin-ip + --insecure to be refused, got: %v", err)
	}
}

func TestPinRecheckedOnReconnect(t *testing.T) {
	f := newFakeTrueNAS(t, func(f *fakeTrueNAS) { f.closeAfter = 1 })
	r := &fakeResolver{addrs: []string{"127.0.0.1"}}
	c := pinnedClient(t, f, r, "127.0.0.1")
	for i := 0; i < 2; i++ {
		if _, err := c.Call("system.info"); err != nil {
			t.Fatalf("Call %d: %v", i, err)
		}
	}
	if n := r.lookups.Load(); n < 2 {
		t.Errorf("DNS checked %d times across 2 connections, want >= 2", n)
	}
}
