package credserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type resolverFunc func(ctx context.Context, req Request) ([]byte, string, error)

func (f resolverFunc) Resolve(ctx context.Context, req Request) ([]byte, string, error) {
	return f(ctx, req)
}

// newServer trusts the uid running the tests, since only root reaches the
// socket in production.
func newServer(r Resolver) *Server {
	srv := New(r, slog.New(slog.NewTextHandler(os.Stderr, nil)), 5*time.Second)
	srv.trustUID = uint32(os.Getuid())
	return srv
}

func startServer(t *testing.T, r Resolver) string {
	t.Helper()
	return serve(t, newServer(r))
}

// serve runs srv on a unix socket in a temp dir and returns its path.
func serve(t *testing.T, srv *Server) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() {
		_ = l.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return socket
}

// fetch connects the way systemd does: from an abstract-namespace socket
// naming the unit and credential.
func fetch(t *testing.T, socket, unit, credential string) ([]byte, error) {
	t.Helper()

	laddr := &net.UnixAddr{
		Net:  "unix",
		Name: fmt.Sprintf("@%x/unit/%s/%s", time.Now().UnixNano(), unit, credential),
	}
	conn, err := net.DialUnix("unix", laddr, &net.UnixAddr{Net: "unix", Name: socket})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

func TestServerServesCredential(t *testing.T) {
	socket := startServer(t, resolverFunc(func(_ context.Context, req Request) ([]byte, string, error) {
		return []byte(req.Unit + "|" + req.Credential), "test/path", nil
	}))

	got, err := fetch(t, socket, "foobar.service", "db-password")
	if err != nil {
		t.Fatal(err)
	}
	if want := "foobar.service|db-password"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestServerReloadSwapsResolver(t *testing.T) {
	srv := newServer(resolverFunc(func(context.Context, Request) ([]byte, string, error) {
		return []byte("before"), "test/path", nil
	}))
	socket := serve(t, srv)

	got, err := fetch(t, socket, "foobar.service", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "before" {
		t.Errorf("got %q, want %q", got, "before")
	}

	srv.Reload(resolverFunc(func(context.Context, Request) ([]byte, string, error) {
		return []byte("after"), "test/path", nil
	}), 5*time.Second)

	got, err = fetch(t, socket, "foobar.service", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "after" {
		t.Errorf("got %q, want %q", got, "after")
	}
}

func TestServerResolverErrorYieldsNoData(t *testing.T) {
	socket := startServer(t, resolverFunc(func(context.Context, Request) ([]byte, string, error) {
		return nil, "", errors.New("no such secret")
	}))

	got, err := fetch(t, socket, "foobar.service", "nope")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want no data", got)
	}
}

func TestServerRejectsNonRootPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, which the server trusts")
	}
	called := false
	// New leaves trustUID zero, which is what production runs with.
	srv := New(resolverFunc(func(context.Context, Request) ([]byte, string, error) {
		called = true
		return []byte("secret"), "test/path", nil
	}), slog.New(slog.NewTextHandler(os.Stderr, nil)), 5*time.Second)

	got, err := fetch(t, serve(t, srv), "foobar.service", "cred")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want no data", got)
	}
	if called {
		t.Error("resolver was consulted for a peer that is not root")
	}
}

func TestServerRejectsUnboundPeer(t *testing.T) {
	called := false
	socket := startServer(t, resolverFunc(func(context.Context, Request) ([]byte, string, error) {
		called = true
		return []byte("secret"), "test/path", nil
	}))

	// Plain Dial binds no source address, so the peer has no abstract name.
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want no data", got)
	}
	if called {
		t.Error("resolver was consulted for a connection without peer metadata")
	}
}

func TestServerStats(t *testing.T) {
	srv := newServer(resolverFunc(func(_ context.Context, req Request) ([]byte, string, error) {
		if req.Credential == "denied" {
			return nil, "", errors.New("no such secret")
		}
		return []byte("ok"), "test/path", nil
	}))
	socket := serve(t, srv)

	// The served counter increments after the requester already has its
	// EOF, so the update signal is what makes Stats current.
	expect := func(served, refused uint64) {
		t.Helper()
		select {
		case <-srv.StatsUpdates():
		case <-time.After(5 * time.Second):
			t.Fatal("no stats update arrived")
		}
		if s, r := srv.Stats(); s != served || r != refused {
			t.Errorf("got %d served, %d refused, want %d served, %d refused", s, r, served, refused)
		}
	}

	if _, err := fetch(t, socket, "foobar.service", "cred"); err != nil {
		t.Fatal(err)
	}
	expect(1, 0)

	if _, err := fetch(t, socket, "foobar.service", "denied"); err != nil {
		t.Fatal(err)
	}
	expect(1, 1)

	// A connection rejected before the protocol even starts is a refusal
	// too: every connection lands in exactly one counter.
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}
	expect(1, 2)
}

func TestServerCredentialSizeLimit(t *testing.T) {
	socket := startServer(t, resolverFunc(func(_ context.Context, req Request) ([]byte, string, error) {
		if req.Credential == "at-limit" {
			return make([]byte, CredentialSizeMax), "test/path", nil
		}
		return make([]byte, CredentialSizeMax+1), "test/path", nil
	}))

	got, err := fetch(t, socket, "foobar.service", "at-limit")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != CredentialSizeMax {
		t.Errorf("got %d bytes, want %d", len(got), CredentialSizeMax)
	}

	got, err = fetch(t, socket, "foobar.service", "oversized")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want no data", len(got))
	}
}
