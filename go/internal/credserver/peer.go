package credserver

import (
	"fmt"
	"net"
	"strings"
)

// Request identifies the systemd unit and credential ID a connection is
// asking for.
//
// The service manager connects from a socket bound to the abstract-namespace
// address "\0RANDOM/unit/UNIT/ID", e.g.
// "\0adf9d86b6eda275e/unit/foobar.service/credx". See the LoadCredential=
// section of systemd.exec(5).
type Request struct {
	// Unit is the requesting unit name, e.g. "foobar.service".
	Unit string
	// Credential is the credential ID being requested, e.g. "credx".
	Credential string
}

// ref names the request the way the log messages do.
func (r Request) ref() string {
	return fmt.Sprintf("%q for %q", r.Credential, r.Unit)
}

// NewRequest applies the shape checks ParsePeer applies, so a request built
// from CLI arguments is refused exactly like one from the socket. Globs are
// matched against whole names and placeholder values join path segments, so
// neither part may be empty or contain a slash.
func NewRequest(unit, credential string) (Request, error) {
	if unit == "" || strings.Contains(unit, "/") {
		return Request{}, fmt.Errorf("invalid unit name %q", unit)
	}
	if credential == "" || strings.Contains(credential, "/") {
		return Request{}, fmt.Errorf("invalid credential ID %q", credential)
	}
	return Request{Unit: unit, Credential: credential}, nil
}

// ParsePeer extracts the requesting unit and credential ID from the peer
// address of an accepted connection. It fails unless the peer is bound to an
// abstract-namespace address in systemd's format, which also rejects ordinary
// clients that connect without binding.
func ParsePeer(addr net.Addr) (Request, error) {
	ua, ok := addr.(*net.UnixAddr)
	if !ok {
		return Request{}, fmt.Errorf("peer address is not a unix address: %T", addr)
	}

	// The Go runtime represents abstract-namespace addresses with a leading "@".
	name, ok := strings.CutPrefix(ua.Name, "@")
	if !ok {
		return Request{}, fmt.Errorf("peer %q is not bound to an abstract-namespace address", ua.Name)
	}

	_, rest, ok := strings.Cut(name, "/unit/")
	if !ok {
		return Request{}, fmt.Errorf("peer address %q does not contain %q", ua.Name, "/unit/")
	}

	unit, credential, ok := strings.Cut(rest, "/")
	if !ok {
		return Request{}, fmt.Errorf("peer address %q does not encode a unit and credential ID", ua.Name)
	}
	req, err := NewRequest(unit, credential)
	if err != nil {
		return Request{}, fmt.Errorf("peer address %q: %w", ua.Name, err)
	}
	return req, nil
}
