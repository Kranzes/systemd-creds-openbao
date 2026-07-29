// Package credserver implements the server side of systemd's credential
// socket protocol: it takes the requesting unit and credential ID from the
// peer address and writes the payload, closing to signal the end of it.
package credserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// CredentialSizeMax is the maximum credential size systemd accepts
// (CREDENTIAL_SIZE_MAX). A larger payload makes the requesting unit fail to
// start, so the server refuses to send one.
const CredentialSizeMax = 1024 * 1024

// Resolver produces the payload for a credential request, along with the
// backend path it came from for logging. Implementations must be safe for
// concurrent use.
type Resolver interface {
	Resolve(ctx context.Context, req Request) ([]byte, string, error)
}

// Server serves systemd credential requests on one or more listeners.
type Server struct {
	log *slog.Logger
	cur atomic.Pointer[serving]

	// trustUID is a second uid to accept beyond root. It is zero in
	// production; the tests set it because they connect as whoever runs them.
	trustUID uint32
}

// serving holds what a reload replaces while the accept loop keeps running.
type serving struct {
	resolver    Resolver
	connTimeout time.Duration
}

// New returns a Server that answers requests using resolver. connTimeout
// bounds the backend fetch and the payload write separately; zero or negative
// means no limit.
func New(resolver Resolver, log *slog.Logger, connTimeout time.Duration) *Server {
	s := &Server{log: log}
	s.Reload(resolver, connTimeout)
	return s
}

// Reload puts a new resolver and connection timeout into effect. A request
// already in flight finishes against the ones it started with.
func (s *Server) Reload(resolver Resolver, connTimeout time.Duration) {
	s.cur.Store(&serving{resolver: resolver, connTimeout: connTimeout})
}

// Serve accepts connections on l until it is closed, then returns nil.
// There is no graceful drain. systemd owns the listening socket, so requests
// arriving during a restart queue in the kernel; only connections in flight at
// that instant are cut off, with an empty credential.
func (s *Server) Serve(l net.Listener) error {
	defer func() { _ = l.Close() }()

	var pause time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Transient resource exhaustion (EMFILE, ECONNABORTED, ...)
			// must not take credential delivery down.
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			s.log.Warn("accept failed, retrying", "ERROR", err, "RETRY_IN", pause)
			time.Sleep(pause)
			continue
		}
		pause = 0

		go s.handle(conn)
	}
}

// handle serves a single credential request.
//
// The protocol has no error channel: systemd reads until EOF and takes
// whatever arrived as the value. Any failure closes the connection unwritten,
// which the requesting unit sees as an empty credential.
func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	uc, ok := conn.(*net.UnixConn)
	if !ok || !s.peerTrusted(uc) {
		s.log.Warn("rejecting connection from untrusted peer")
		return
	}

	cur := s.cur.Load()

	ctx := context.Background()
	if cur.connTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cur.connTimeout)
		defer cancel()
	}

	req, err := ParsePeer(conn.RemoteAddr())
	if err != nil {
		s.log.Warn("rejecting connection that does not speak the systemd credential protocol", "ERROR", err)
		return
	}
	log := s.log.With("UNIT", req.Unit, "CREDENTIAL", req.Credential)
	ref := fmt.Sprintf("%q for %q", req.Credential, req.Unit)

	data, secretPath, err := cur.resolver.Resolve(ctx, req)
	if err != nil {
		log.Error(fmt.Sprintf("refusing credential %s: %v", ref, err), "ERROR", err)
		return
	}
	log = log.With("SECRET_PATH", secretPath)
	if len(data) > CredentialSizeMax {
		log.Error("refusing credential "+ref+": payload exceeds systemd's credential size limit",
			"SIZE", len(data), "LIMIT", CredentialSizeMax)
		return
	}

	// The write gets a budget of its own rather than the fetch's leftovers: a
	// deadline that expires part way through hands the requester the bytes
	// already queued, which it reads as a complete credential.
	if cur.connTimeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(cur.connTimeout)); err != nil {
			log.Error(fmt.Sprintf("failed to set write deadline serving %s: %v", ref, err), "ERROR", err)
			return
		}
	}
	if n, err := conn.Write(data); err != nil {
		log.Error(fmt.Sprintf("failed to write credential %s: %v", ref, err), "ERROR", err, "WRITTEN", n, "SIZE", len(data))
		return
	}
	// Half-close so the requester sees EOF promptly.
	_ = uc.CloseWrite()
	log.Info(fmt.Sprintf("served credential %q from %q for %q", req.Credential, secretPath, req.Unit))
}

// peerTrusted reports whether the peer is the service manager. A client
// asserts its own identity through the peer name, so a misconfigured
// SocketMode= must not expose the socket to anyone else.
func (s *Server) peerTrusted(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var (
		cred    *syscall.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return false
	}
	return cred.Uid == 0 || (s.trustUID != 0 && cred.Uid == s.trustUID)
}
