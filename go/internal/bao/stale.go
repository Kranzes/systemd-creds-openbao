package bao

import (
	"context"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

// reader is the part of *Client that StaleCache decorates.
type reader interface {
	Read(ctx context.Context, ref config.SecretRef) (map[string]any, error)
}

// StaleCache decorates Client with a fallback for OpenBao outages: it
// remembers the last successful response per secret and serves it when a
// fresh read fails with a transient error, so a service can still start
// while OpenBao is unreachable. No fresh read is ever skipped, and an
// authoritative refusal (permission denied, missing secret) is returned
// as-is; only errors OpenBao never got to answer fall back. It implements
// secrets.Reader and is safe for concurrent use.
type StaleCache struct {
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	inner   reader
	maxAge  time.Duration
	entries map[config.SecretRef]entry
}

type entry struct {
	data map[string]any
	at   time.Time
}

// sweepInterval is how often expired entries are reclaimed in the background.
// It bounds how long an entry that can no longer be served keeps secret
// material in memory past maxAge. A variable so tests can shorten it.
var sweepInterval = time.Minute

// NewStaleCache wraps inner, serving stale responses up to maxAge old; zero
// disables the fallback and retains nothing. Expired entries are reclaimed in
// the background until ctx is canceled.
func NewStaleCache(ctx context.Context, inner reader, maxAge time.Duration, log *slog.Logger) *StaleCache {
	s := &StaleCache{
		log:     log,
		now:     time.Now,
		inner:   inner,
		maxAge:  maxAge,
		entries: map[config.SecretRef]entry{},
	}
	go s.sweepLoop(ctx)
	return s
}

// sweepLoop reclaims expired entries until ctx is canceled. Read only ever
// revisits the ref in front of it, so without the sweep a secret read once
// and never again would stay resident for the daemon's lifetime, and rules
// serving per-instance paths would grow the map without bound.
func (s *StaleCache) sweepLoop(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			s.removeExpired()
			s.mu.Unlock()
		}
	}
}

// removeExpired drops the entries past maxAge. The caller holds mu.
func (s *StaleCache) removeExpired() {
	now := s.now()
	maps.DeleteFunc(s.entries, func(_ config.SecretRef, e entry) bool {
		return now.Sub(e.at) > s.maxAge
	})
}

// Swap installs the client and staleness bound a reload produced. Entries
// carry over, so a reload during an outage keeps the fallback. Disabling
// drops them: secret material is only retained while it can be served.
func (s *StaleCache) Swap(inner reader, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inner = inner
	s.maxAge = maxAge
	if maxAge <= 0 {
		clear(s.entries)
		return
	}
	// A bound the reload shrank takes effect now rather than at the next sweep.
	s.removeExpired()
}

// Read implements secrets.Reader. It does the fresh read and falls back to the
// remembered response only when that fails with a transient error.
func (s *StaleCache) Read(ctx context.Context, key config.SecretRef) (map[string]any, error) {
	s.mu.Lock()
	inner := s.inner
	s.mu.Unlock()

	data, err := inner.Read(ctx, key)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		if s.maxAge > 0 {
			s.entries[key] = entry{data: data, at: s.now()}
		}
		return data, nil
	}
	if !retryable(err) {
		// An authoritative answer supersedes the remembered response: a
		// secret OpenBao revoked or deleted must not resurface during a
		// later outage.
		delete(s.entries, key)
		return nil, err
	}
	e, ok := s.entries[key]
	if !ok {
		return nil, err
	}
	if age := s.now().Sub(e.at); age <= s.maxAge {
		s.log.Warn("read failed, serving stale secret data", "SECRET_PATH", key.Location(), "AGE", age, "ERROR", err)
		return e.data, nil
	}
	// Past the bound the entry can never be served again, so it must not
	// linger in memory.
	delete(s.entries, key)
	return nil, err
}
