package bao

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// reader is the part of *Client that StaleCache decorates.
type reader interface {
	ReadKV(ctx context.Context, mount, secretPath string) (map[string]any, error)
	ReadRaw(ctx context.Context, apiPath string) (map[string]any, error)
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
	entries map[readKey]entry
}

type readKey struct {
	raw         bool
	mount, path string
}

type entry struct {
	data map[string]any
	at   time.Time
}

// NewStaleCache wraps inner, serving stale responses up to maxAge old; zero
// disables the fallback and retains nothing.
func NewStaleCache(inner reader, maxAge time.Duration, log *slog.Logger) *StaleCache {
	return &StaleCache{
		log:     log,
		now:     time.Now,
		inner:   inner,
		maxAge:  maxAge,
		entries: map[readKey]entry{},
	}
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
	}
}

// ReadKV implements secrets.Reader.
func (s *StaleCache) ReadKV(ctx context.Context, mount, secretPath string) (map[string]any, error) {
	return s.read(ctx, readKey{mount: mount, path: secretPath}, mount+"/"+secretPath)
}

// ReadRaw implements secrets.Reader.
func (s *StaleCache) ReadRaw(ctx context.Context, apiPath string) (map[string]any, error) {
	return s.read(ctx, readKey{raw: true, path: apiPath}, apiPath)
}

// read does the fresh read and falls back to the remembered response only
// when the read fails with a transient error. location names the secret the
// way the journal's SECRET_PATH field does.
func (s *StaleCache) read(ctx context.Context, key readKey, location string) (map[string]any, error) {
	s.mu.Lock()
	inner := s.inner
	s.mu.Unlock()

	var data map[string]any
	var err error
	if key.raw {
		data, err = inner.ReadRaw(ctx, key.path)
	} else {
		data, err = inner.ReadKV(ctx, key.mount, key.path)
	}

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
		s.log.Warn("read failed, serving stale secret data", "SECRET_PATH", location, "AGE", age, "ERROR", err)
		return e.data, nil
	}
	// Past the bound the entry can never be served again, so it must not
	// linger in memory.
	delete(s.entries, key)
	return nil, err
}
