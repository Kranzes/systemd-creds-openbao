package bao

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

// flakyReader serves fixed data until failWith is set.
type flakyReader struct {
	data     map[string]any
	failWith error
	calls    int
}

func (f *flakyReader) Read(_ context.Context, _ config.SecretRef) (map[string]any, error) {
	f.calls++
	if f.failWith != nil {
		return nil, f.failWith
	}
	return f.data, nil
}

var errDown = &url.Error{Op: "Get", URL: "http://bao", Err: errors.New("connection refused")}

// testStaleCache wraps inner with a clock the test advances via the returned
// pointer. It builds the struct directly, so no sweep goroutine runs and the
// fake clock needs no synchronization.
func testStaleCache(inner reader, maxAge time.Duration) (*StaleCache, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &StaleCache{
		log:     testLogger(),
		inner:   inner,
		maxAge:  maxAge,
		entries: map[config.SecretRef]entry{},
	}
	c.now = func() time.Time { return now }
	return c, &now
}

func readKV(t *testing.T, c *StaleCache) (map[string]any, error) {
	t.Helper()
	return c.Read(context.Background(), config.SecretRef{Mount: "kv", Path: "myapp/db"})
}

func TestStaleCacheReadsFreshWhileHealthy(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	for range 2 {
		got, err := readKV(t, c)
		if err != nil {
			t.Fatal(err)
		}
		if got["password"] != "hunter2" {
			t.Fatalf("got %v", got)
		}
	}
	if inner.calls != 2 {
		t.Fatalf("expected every request to reach OpenBao, got %d reads", inner.calls)
	}
}

func TestStaleCacheServesStaleOnTransientError(t *testing.T) {
	// A failed certificate verification is a transport outage like a refused
	// connection. Only the login path treats it as definitive.
	certDown := &url.Error{Op: "Get", URL: "https://bao", Err: &tls.CertificateVerificationError{}}
	for _, transient := range []error{errDown, certDown} {
		inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
		c, clock := testStaleCache(inner, time.Hour)

		if _, err := readKV(t, c); err != nil {
			t.Fatal(err)
		}
		inner.failWith = transient
		*clock = clock.Add(59 * time.Minute)
		got, err := readKV(t, c)
		if err != nil {
			t.Fatalf("%v: expected stale data, got error %v", transient, err)
		}
		if got["password"] != "hunter2" {
			t.Fatalf("%v: got %v", transient, got)
		}
	}
}

// A hung server surfaces as a bare context error rather than a url.Error,
// and is an outage like any other.
func TestStaleCacheServesStaleOnContextDeadline(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	inner.failWith = context.DeadlineExceeded
	got, err := readKV(t, c)
	if err != nil {
		t.Fatalf("expected stale data, got %v", err)
	}
	if got["password"] != "hunter2" {
		t.Fatalf("got %v", got)
	}
}

func TestStaleCacheRespectsMaxAge(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, clock := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	inner.failWith = errDown
	*clock = clock.Add(61 * time.Minute)
	if _, err := readKV(t, c); !errors.Is(err, errDown) {
		t.Fatalf("expected the read error past the bound, got %v", err)
	}
	if len(c.entries) != 0 {
		t.Fatal("expired entry was retained")
	}
}

func TestStaleCacheAgeCountsFromLastSuccess(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, clock := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(40 * time.Minute)
	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(40 * time.Minute)
	inner.failWith = errDown
	if _, err := readKV(t, c); err != nil {
		t.Fatalf("expected stale data 40m after the last success, got %v", err)
	}
}

func TestStaleCacheNeverMasksAuthoritativeErrors(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		&api.ResponseError{StatusCode: http.StatusForbidden},
		api.ErrSecretNotFound,
	} {
		inner.failWith = err
		if _, got := readKV(t, c); !errors.Is(got, err) {
			t.Fatalf("expected %v, got %v", err, got)
		}
	}
}

func TestStaleCacheAuthoritativeErrorInvalidatesEntry(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	// Access revoked, then OpenBao goes down: the pre-revocation value must
	// not resurface.
	inner.failWith = &api.ResponseError{StatusCode: http.StatusForbidden}
	if _, err := readKV(t, c); err == nil {
		t.Fatal("expected the permission error")
	}
	inner.failWith = errDown
	if _, err := readKV(t, c); !errors.Is(err, errDown) {
		t.Fatalf("expected the read error, got %v", err)
	}
}

// readerFunc lets a test drive each Read call from a function.
type readerFunc func(ctx context.Context, ref config.SecretRef) (map[string]any, error)

func (f readerFunc) Read(ctx context.Context, ref config.SecretRef) (map[string]any, error) {
	return f(ctx, ref)
}

// A slow successful read must not store data a concurrent authoritative
// refusal invalidated, or the revoked value resurfaces during a later outage
// with a fresh timestamp.
func TestStaleCacheSlowReadDoesNotOutliveARefusal(t *testing.T) {
	started := make(chan struct{})
	unblock := make(chan struct{})
	denied := &api.ResponseError{StatusCode: http.StatusForbidden}
	var calls atomic.Int32
	inner := readerFunc(func(context.Context, config.SecretRef) (map[string]any, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-unblock
			return map[string]any{"password": "hunter2"}, nil
		}
		return nil, denied
	})
	c, _ := testStaleCache(inner, time.Hour)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Read(context.Background(), config.SecretRef{Mount: "kv", Path: "myapp/db"})
	}()
	<-started
	if _, err := readKV(t, c); !errors.Is(err, denied) {
		t.Fatalf("expected the permission error, got %v", err)
	}
	close(unblock)
	<-done

	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != 0 {
		t.Fatal("the slow read stored an entry the refusal had invalidated")
	}
}

// A refusal suppresses the store of any read that overlapped it, so the next
// read after the refusal must store again.
func TestStaleCacheStoresAgainAfterARefusal(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	inner.failWith = &api.ResponseError{StatusCode: http.StatusForbidden}
	if _, err := readKV(t, c); err == nil {
		t.Fatal("expected the permission error")
	}
	inner.failWith = nil
	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	inner.failWith = errDown
	if _, err := readKV(t, c); err != nil {
		t.Fatalf("expected stale data from the read after the refusal, got %v", err)
	}
}

// A 403 blamed on the daemon's own token must serve stale and keep the entry.
// With a static token this is exactly the failure the daemon cannot self-heal,
// so it is where the fallback matters most.
func TestStaleCacheServesStaleWhenTheTokenIsRejected(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	inner.failWith = &tokenFaultError{
		reason: "OpenBao rejected the daemon's token",
		err:    &api.ResponseError{StatusCode: http.StatusForbidden},
	}
	got, err := readKV(t, c)
	if err != nil {
		t.Fatalf("expected stale data, got %v", err)
	}
	if got["password"] != "hunter2" {
		t.Fatalf("got %v", got)
	}
	if len(c.entries) != 1 {
		t.Fatal("entry was dropped on a token rejection")
	}
}

// The remembered response is the cache's own copy down to nested values. A
// caller mutating what it was served must not change what the next outage
// serves.
func TestStaleCacheServesUnmutatedData(t *testing.T) {
	inner := &flakyReader{data: map[string]any{
		"password": "hunter2",
		"metadata": map[string]any{"version": "4"},
	}}
	c, _ := testStaleCache(inner, time.Hour)

	fresh, err := readKV(t, c)
	if err != nil {
		t.Fatal(err)
	}
	fresh["password"] = "poisoned"

	inner.failWith = errDown
	stale, err := readKV(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if stale["password"] != "hunter2" {
		t.Fatalf("stale data = %v, want the value as fetched", stale)
	}
	stale["password"] = "poisoned"
	nested, ok := stale["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("stale data = %v, want a nested map", stale)
	}
	nested["version"] = "poisoned"
	again, err := readKV(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if again["password"] != "hunter2" {
		t.Fatalf("stale data = %v, want the value as fetched", again)
	}
	if nested, ok = again["metadata"].(map[string]any); !ok || nested["version"] != "4" {
		t.Fatalf("nested stale data = %v, want the value as fetched", again["metadata"])
	}
}

func TestStaleCacheDisabledRetainsNothing(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, 0)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	if len(c.entries) != 0 {
		t.Fatal("disabled cache retained an entry")
	}
	inner.failWith = errDown
	if _, err := readKV(t, c); !errors.Is(err, errDown) {
		t.Fatalf("expected the read error, got %v", err)
	}
}

func TestStaleCacheKeysRawAndKVSeparately(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	raw := config.SecretRef{Raw: true, Path: "kv/myapp/db"}
	if _, err := c.Read(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	inner.failWith = errDown
	// The KV read resolves to the same location string, but the remembered
	// raw response must not satisfy it.
	if _, err := readKV(t, c); !errors.Is(err, errDown) {
		t.Fatalf("expected the read error, got %v", err)
	}
}

// An entry outliving maxAge has to be reclaimed without a reload or a request
// revisiting it. The sweep is what limits how long a daemon left alone keeps
// secret material resident.
func TestStaleCacheSweepsExpiredEntriesInTheBackground(t *testing.T) {
	defer func(d time.Duration) { sweepInterval = d }(sweepInterval)
	sweepInterval = 10 * time.Millisecond

	// The clock jumps past maxAge via an atomic: the sweep goroutine reads it
	// concurrently with the flip.
	var expired atomic.Bool
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c := NewStaleCache(t.Context(), inner, time.Hour, testLogger())
	c.mu.Lock()
	c.now = func() time.Time {
		if expired.Load() {
			return base.Add(61 * time.Minute)
		}
		return base
	}
	c.mu.Unlock()

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	expired.Store(true)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expired entry was not swept in the background")
}

func TestStaleCacheSwapKeepsEntries(t *testing.T) {
	healthy := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(healthy, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	c.Swap(&flakyReader{failWith: errDown}, time.Hour)
	got, err := readKV(t, c)
	if err != nil {
		t.Fatalf("expected the entry to survive the swap, got %v", err)
	}
	if got["password"] != "hunter2" {
		t.Fatalf("got %v", got)
	}
}

func TestStaleCacheSwapToZeroDropsEntries(t *testing.T) {
	inner := &flakyReader{data: map[string]any{"password": "hunter2"}}
	c, _ := testStaleCache(inner, time.Hour)

	if _, err := readKV(t, c); err != nil {
		t.Fatal(err)
	}
	c.Swap(inner, 0)
	c.Swap(inner, time.Hour)
	inner.failWith = errDown
	if _, err := readKV(t, c); !errors.Is(err, errDown) {
		t.Fatalf("expected the read error after disabling dropped the entries, got %v", err)
	}
}
