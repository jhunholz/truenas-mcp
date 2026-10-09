package truenas

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

// Resolver looks up a host's addresses. *net.Resolver satisfies it.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// PinError is a refusal to connect or authenticate because the destination
// is not the pinned address. The API key has not been sent when it occurs.
type PinError struct{ msg string }

func (e *PinError) Error() string { return "refusing: " + e.msg + "; key not sent" }

// checkResolvesOnlyTo requires every A/AAAA answer for host to be pin, so a
// resolver that answers anything else fails closed.
func checkResolvesOnlyTo(ctx context.Context, r Resolver, host string, pin net.IP) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return &PinError{fmt.Sprintf("cannot resolve %s: %v", host, err)}
	}
	if len(addrs) == 0 {
		return &PinError{fmt.Sprintf("%s resolves to nothing, not %s", host, pin)}
	}
	ips := make([]string, len(addrs))
	ok := true
	for i, a := range addrs {
		ips[i] = a.IP.String()
		if !a.IP.Equal(pin) {
			ok = false
		}
	}
	if !ok {
		return &PinError{fmt.Sprintf("%s resolves to %v, not only %s", host, ips, pin)}
	}
	return nil
}

// pinnedDialContext dials pin on the requested port whatever the hostname,
// like curl --resolve. TLS still verifies the certificate against the
// hostname, because the websocket dialer sets SNI from the URL.
func pinnedDialContext(pin net.IP) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, net.JoinHostPort(pin.String(), port))
	}
}

// checkPeer is the backstop: the socket actually connected must be the pin.
func checkPeer(addr net.Addr, pin net.IP) error {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || !tcp.IP.Equal(pin) {
		return &PinError{fmt.Sprintf("connected to %v, not %s", addr, pin)}
	}
	return nil
}

func underlyingRemoteAddr(conn *websocket.Conn) net.Addr {
	return conn.UnderlyingConn().RemoteAddr()
}
