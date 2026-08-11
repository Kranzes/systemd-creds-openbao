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

// StaleCache decorates Client with a fallback for OpenBao outages. It
// remembers the last successful response per secret and serves it when a
// fresh read fails with a transient error, so a service can still start
// while OpenBao is unreachable. No fresh read is ever skipped, and an
// authoritative refusal (permission denied, missing secret) is returned
// as-is. The fallback only covers errors OpenBao never got to answer. It
// implements secrets.Reader and is safe for concurrent use.
type StaleCache struct {
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	inner   reader
	maxAge  time.Duration
	entries map[config.SecretRef]entry
	// gen counts authoritative refusals and only ever grows. A successful
	// read that overlapped one may carry data from before it, so its store
	// is skipped. One counter for the whole cache over-suppresses, a read
	// overlapping an unrelated refusal skips a store that the next request
	// refills, and in exchange the counter cannot collide and holds no
	// per-key state that a requester could grow.
	gen uint64
}

type entry struct {
	data map[string]any
	at   time.Time
}

// sweepInterval is how often expired entries are reclaimed in the background.
// An entry that can no longer be served keeps secret material in memory for
// at most this long past maxAge. A variable so tests can shorten it.
var sweepInterval = time.Minute

// NewStaleCache wraps inner, serving stale responses up to maxAge old. Zero
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
// serving per-instance paths would keep growing the map.
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

// cloneData copies data deeply enough that no caller can reach what the
// cache holds. Maps and slices are the containers secret data nests, every
// other JSON value is immutable to a reader.
func cloneData(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		return cloneData(v)
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = cloneValue(e)
		}
		return out
	default:
		return v
	}
}

// removeExpired drops the entries past maxAge. The caller holds mu.
func (s *StaleCache) removeExpired() {
	now := s.now()
	maps.DeleteFunc(s.entries, func(_ config.SecretRef, e entry) bool {
		return now.Sub(e.at) > s.maxAge
	})
}

// Swap installs the client and max age a reload produced. Entries
// carry over, so a reload during an outage keeps the fallback. Disabling
// drops them, since secret material is only retained while it can be served.
func (s *StaleCache) Swap(inner reader, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inner = inner
	s.maxAge = maxAge
	if maxAge <= 0 {
		clear(s.entries)
		return
	}
	// A max age the reload shrank takes effect now rather than at the next sweep.
	s.removeExpired()
}

// Read implements secrets.Reader. It does the fresh read and falls back to the
// remembered response only when that fails with a transient error.
func (s *StaleCache) Read(ctx context.Context, key config.SecretRef) (map[string]any, error) {
	s.mu.Lock()
	inner, gen := s.inner, s.gen
	s.mu.Unlock()

	data, err := inner.Read(ctx, key)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		if s.maxAge > 0 && s.gen == gen {
			// The cache keeps its own copy, so nothing a caller does to the
			// returned data can change what a later outage serves.
			s.entries[key] = entry{data: cloneData(data), at: s.now()}
		}
		return data, nil
	}
	if !retryable(err) {
		// An authoritative answer supersedes the remembered response. A
		// secret OpenBao revoked or deleted must not resurface during a
		// later outage.
		delete(s.entries, key)
		s.gen++
		return nil, err
	}
	e, ok := s.entries[key]
	if !ok {
		return nil, err
	}
	if age := s.now().Sub(e.at); age <= s.maxAge {
		s.log.Warn("read failed, serving stale secret data", "SECRET_PATH", key.Location(), "AGE", age, "ERROR", err)
		return cloneData(e.data), nil
	}
	// Past maxAge the entry can never be served again, so it must not
	// linger in memory.
	delete(s.entries, key)
	return nil, err
}
