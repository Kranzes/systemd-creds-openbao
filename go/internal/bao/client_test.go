package bao

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// fakeBao is a minimal OpenBao API stand-in.
func fakeBao(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	respond := func(w http.ResponseWriter, body any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}

	mux.HandleFunc("/v1/secret/data/myapp/db", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		respond(w, map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"password": "hunter2"},
				"metadata": map[string]any{"version": 4},
			},
		})
	})
	mux.HandleFunc("/v1/database/creds/myapp", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, map[string]any{
			"lease_id":       "database/creds/myapp/abc",
			"lease_duration": 3600,
			"data":           map[string]any{"username": "u", "password": "p"},
		})
	})
	mux.HandleFunc("/v1/secret/data/myapp/deleted", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, map[string]any{
			"data": map[string]any{
				"data":     nil,
				"metadata": map[string]any{"version": 2, "deletion_time": "2026-07-01T00:00:00Z"},
			},
		})
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		respond(w, map[string]any{"errors": []string{"lease is not renewable"}})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			respond(w, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		respond(w, map[string]any{"data": map[string]any{"id": "test-token"}})
	})
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body["role_id"] == "tokenless" {
			respond(w, map[string]any{"auth": map[string]any{"client_token": ""}})
			return
		}
		if body["role_id"] != "my-role" || body["secret_id"] != "my-secret" {
			w.WriteHeader(http.StatusForbidden)
			respond(w, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		respond(w, map[string]any{
			"auth": map[string]any{
				"client_token":   "approle-token",
				"renewable":      false,
				"lease_duration": 0,
			},
		})
	})

	mux.HandleFunc("/v1/auth/jwt/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body["jwt"] != "my-jwt" || body["role"] != "my-role" {
			w.WriteHeader(http.StatusForbidden)
			respond(w, map[string]any{"errors": []string{"invalid JWT or role"}})
			return
		}
		respond(w, map[string]any{
			"auth": map[string]any{
				"client_token":   "jwt-token",
				"renewable":      false,
				"lease_duration": 0,
			},
		})
	})

	mux.HandleFunc("/v1/auth/cert/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if name, ok := body["name"]; ok && name != "" && name != "web-servers" {
			w.WriteHeader(http.StatusForbidden)
			respond(w, map[string]any{"errors": []string{"unknown certificate role"}})
			return
		}
		respond(w, map[string]any{
			"auth": map[string]any{
				"client_token":   "cert-token",
				"renewable":      false,
				"lease_duration": 0,
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// writeClientCert writes a self-signed certificate and key. The fake server
// never verifies them, but the client library refuses to start without a
// loadable pair.
func writeClientCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func certConfig(t *testing.T, srv *httptest.Server, certRole string) config.OpenBao {
	t.Helper()
	certFile, keyFile := writeClientCert(t)
	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_CLIENT_CERT", certFile)
	t.Setenv("BAO_CLIENT_KEY", keyFile)

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthCert
	cfg.Auth.Mount = "cert"
	cfg.Auth.CertRole = certRole
	return cfg
}

// tokenConfig points the client at srv through the environment, the only way
// the connection and a static token are configured.
func tokenConfig(t *testing.T, srv *httptest.Server) config.OpenBao {
	t.Helper()
	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_TOKEN", "test-token")
	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthToken
	return cfg
}

func approleConfig(t *testing.T, srv *httptest.Server, roleID, secretID string) config.OpenBao {
	t.Helper()
	t.Setenv("BAO_ADDR", srv.URL)

	secretIDFile := filepath.Join(t.TempDir(), "secret-id")
	if err := os.WriteFile(secretIDFile, []byte(secretID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthAppRole
	cfg.Auth.Mount = "approle"
	cfg.Auth.RoleID = roleID
	cfg.Auth.SecretIDFile = secretIDFile
	return cfg
}

func jwtConfig(t *testing.T, srv *httptest.Server, jwt, role string) config.OpenBao {
	t.Helper()
	t.Setenv("BAO_ADDR", srv.URL)

	jwtFile := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(jwtFile, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthJWT
	cfg.Auth.Mount = "jwt"
	cfg.Auth.JWTFile = jwtFile
	cfg.Auth.JWTRole = role
	return cfg
}

// handleLookupSelf accepts any token, for muxes built around other endpoints.
// Token authentication checks the token through lookup-self.
func handleLookupSelf(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "t"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
}

// testClient returns a token-authenticated Client backed by fakeBao.
func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(context.Background(), tokenConfig(t, fakeBao(t)), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// kvRef names a secret on the "secret" mount the fake OpenBao serves.
func kvRef(path string) config.SecretRef {
	return config.SecretRef{Mount: "secret", Path: path}
}

func TestReadKV(t *testing.T) {
	client := testClient(t)

	data, err := client.Read(context.Background(), kvRef("myapp/db"))
	if err != nil {
		t.Fatal(err)
	}
	if data["password"] != "hunter2" {
		t.Errorf("data = %v", data)
	}
}

func TestReadRaw(t *testing.T) {
	client := testClient(t)

	data, err := client.Read(context.Background(), config.SecretRef{Raw: true, Path: "database/creds/myapp"})
	if err != nil {
		t.Fatal(err)
	}
	if data["username"] != "u" || data["password"] != "p" {
		t.Errorf("data = %v", data)
	}
}

func TestReadRejectsOversizedResponse(t *testing.T) {
	// The client library buffers a whole response, and tees it into a second
	// buffer to parse it, before anything looks at how big it is, so the limit
	// has to cut the body off at the transport. The body here stays valid JSON
	// so that only its size can be what fails the read.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/big", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"data":{"password":"`)
		chunk := strings.Repeat("a", 1<<20)
		for n := 0; n <= responseSizeMax; n += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `"},"metadata":{"version":1}}}`)
	})
	handleLookupSelf(t, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := t.Context()
	c, err := New(ctx, tokenConfig(t, srv), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Read(ctx, kvRef("big"))
	if err == nil {
		t.Fatal("ReadKV succeeded, want the response refused for its size")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error %q does not report the size limit", err)
	}
	// A secret does not shrink on retry. Classified transient, the failure
	// would be retried forever and, serving stale, never reach the journal.
	if retryable(err) {
		t.Errorf("size-limit error %q classified retryable, want authoritative", err)
	}
}

// The declared length refuses the response at RoundTrip, whose error net/http
// wraps in a *url.Error. The classification has to survive that wrapping.
func TestReadRejectsOversizedResponseByContentLength(t *testing.T) {
	t.Setenv("BAO_MAX_RETRIES", "0")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/big", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(responseSizeMax+1))
		w.WriteHeader(http.StatusOK)
	})
	handleLookupSelf(t, mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx := t.Context()
	c, err := New(ctx, tokenConfig(t, srv), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Read(ctx, kvRef("big"))
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want the response refused for its declared size", err)
	}
	if retryable(err) {
		t.Errorf("size-limit error %q classified retryable, want authoritative", err)
	}
}

// A 403 read means one thing with a valid token (this path is denied) and
// another with a rejected one (OpenBao never judged the path). Only the first
// may count as authoritative and drop what StaleCache remembers.
func TestReadForbiddenClassification(t *testing.T) {
	var tokenValid, probeDown atomic.Bool
	mux := http.NewServeMux()
	forbid := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}
	mux.HandleFunc("/v1/secret/data/denied", func(w http.ResponseWriter, _ *http.Request) {
		forbid(w)
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		if probeDown.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !tokenValid.Load() {
			forbid(w)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "test-token"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]any{"errors": []string{"lease is not renewable"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	tokenValid.Store(true)
	client, err := New(context.Background(), tokenConfig(t, srv), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Read(context.Background(), kvRef("denied"))
	if err == nil || retryable(err) {
		t.Errorf("403 with a valid token classified retryable (err = %v), want authoritative", err)
	}

	tokenValid.Store(false)
	_, err = client.Read(context.Background(), kvRef("denied"))
	if err == nil || !retryable(err) {
		t.Errorf("403 with a rejected token classified authoritative (err = %v), want retryable", err)
	}
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q does not blame the token", err)
	}

	// A probe that gets no answer leaves the 403 unexplained, and an
	// unexplained refusal must not count as authoritative.
	probeDown.Store(true)
	_, err = client.Read(context.Background(), kvRef("denied"))
	if err == nil || !retryable(err) {
		t.Errorf("403 with an unanswered token check classified authoritative (err = %v), want retryable", err)
	}
}

func TestReadKVNotFound(t *testing.T) {
	client := testClient(t)

	if _, err := client.Read(context.Background(), kvRef("does/not/exist")); err == nil {
		t.Error("ReadKV succeeded for a missing secret, want error")
	}
}

func TestReadKVDeletedVersion(t *testing.T) {
	client := testClient(t)

	_, err := client.Read(context.Background(), kvRef("myapp/deleted"))
	if err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Errorf("err = %v, want deleted-version error", err)
	}
}

func TestTokenFromFile(t *testing.T) {
	srv := fakeBao(t)
	t.Setenv("BAO_ADDR", srv.URL)

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthToken
	cfg.Auth.TokenFile = tokenFile

	client, err := New(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(context.Background(), kvRef("myapp/db")); err != nil {
		t.Errorf("read with file token failed: %v", err)
	}
}

func TestTokenFileEnvExpansion(t *testing.T) {
	srv := fakeBao(t)
	t.Setenv("BAO_ADDR", srv.URL)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthToken
	cfg.Auth.TokenFile = "${CREDENTIALS_DIRECTORY}/token"

	client, err := New(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(context.Background(), kvRef("myapp/db")); err != nil {
		t.Errorf("read with expanded token file failed: %v", err)
	}
}

func TestTokenFileUnsetEnvVarFails(t *testing.T) {
	srv := fakeBao(t)
	t.Setenv("BAO_ADDR", srv.URL)
	// t.Setenv registers the restore. The test needs the variable absent.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	_ = os.Unsetenv("CREDENTIALS_DIRECTORY")

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthToken
	cfg.Auth.TokenFile = "${CREDENTIALS_DIRECTORY}/token"

	// An unset variable must fail, not silently read the unrelated path
	// "/token".
	_, err := New(context.Background(), cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Errorf("err = %v, want undefined-variable error", err)
	}
}

func TestAppRoleLogin(t *testing.T) {
	cfg := approleConfig(t, fakeBao(t), "my-role", "my-secret")

	client, err := New(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := client.api.Token(); got != "approle-token" {
		t.Errorf("client token = %q, want %q", got, "approle-token")
	}
}

func TestAppRoleLoginRejected(t *testing.T) {
	cfg := approleConfig(t, fakeBao(t), "wrong", "wrong")

	if _, err := New(context.Background(), cfg, testLogger()); err == nil {
		t.Error("New succeeded with rejected approle login, want error")
	}
}

func TestAppRoleLoginWithoutTokenFails(t *testing.T) {
	cfg := approleConfig(t, fakeBao(t), "tokenless", "anything")

	// A 200 login response with no client token must fail, not succeed with
	// an empty token.
	if _, err := New(context.Background(), cfg, testLogger()); err == nil {
		t.Error("New succeeded despite a tokenless login response, want error")
	}
}

func TestJWTLogin(t *testing.T) {
	cfg := jwtConfig(t, fakeBao(t), "my-jwt", "my-role")

	client, err := New(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := client.api.Token(); got != "jwt-token" {
		t.Errorf("client token = %q, want %q", got, "jwt-token")
	}
}

func TestJWTLoginRejected(t *testing.T) {
	cfg := jwtConfig(t, fakeBao(t), "wrong", "my-role")

	if _, err := New(context.Background(), cfg, testLogger()); err == nil {
		t.Error("New succeeded with rejected JWT login, want error")
	}
}

func TestJWTLoginEmptyFile(t *testing.T) {
	cfg := jwtConfig(t, fakeBao(t), "", "my-role")

	// An empty jwt_file must fail, not send an empty JWT.
	_, err := New(context.Background(), cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("err = %v, want empty-file error", err)
	}
}

func TestCertLogin(t *testing.T) {
	cfg := certConfig(t, fakeBao(t), "web-servers")

	client, err := New(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := client.api.Token(); got != "cert-token" {
		t.Errorf("client token = %q, want %q", got, "cert-token")
	}
}

func TestCertLoginUnknownRole(t *testing.T) {
	cfg := certConfig(t, fakeBao(t), "nonexistent")

	if _, err := New(context.Background(), cfg, testLogger()); err == nil {
		t.Error("New succeeded with unknown certificate role, want error")
	}
}

func TestCertLoginWithoutClientCert(t *testing.T) {
	srv := fakeBao(t)
	t.Setenv("BAO_ADDR", srv.URL)
	for _, v := range []string{
		"BAO_CLIENT_CERT", "BAO_CLIENT_CERT_BYTES",
		"VAULT_CLIENT_CERT", "VAULT_CLIENT_CERT_BYTES",
	} {
		// t.Setenv registers the restore. The test needs the variable absent.
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthCert
	cfg.Auth.Mount = "cert"

	_, err := New(context.Background(), cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Errorf("err = %v, want missing-client-certificate error", err)
	}
}

// A login that cannot verify the server certificate must fail the unit, not
// back off forever with the cause buried in retry warnings.
func TestLoginFailsFastOnCertificateVerificationFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	// No BAO_CACERT, so the self-signed server certificate cannot verify.
	cfg := approleConfig(t, srv, "my-role", "my-secret")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := New(ctx, cfg, testLogger())
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Errorf("err = %v, want a certificate verification failure without retries", err)
	}
}

func TestStaticTokenRenewalProbe(t *testing.T) {
	probed := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case probed <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]any{"errors": []string{"lease is not renewable"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	handleLookupSelf(t, mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if _, err := New(context.Background(), tokenConfig(t, srv), testLogger()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("renew-self was never attempted for the static token")
	}
}

// A 500 must not be read as "not renewable". See renewStaticToken.
func TestStaticTokenRenewalRetriesTransientFailure(t *testing.T) {
	var attempts atomic.Int32
	renewed := make(chan struct{})
	mux := http.NewServeMux()
	t.Setenv("BAO_MAX_RETRIES", "0") // exercise our retry, not the api client's
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "renewed-token",
				"lease_duration": 3600,
				"renewable":      false,
			},
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
		select {
		case <-renewed:
		default:
			close(renewed)
		}
	})
	handleLookupSelf(t, mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := New(ctx, tokenConfig(t, srv), testLogger()); err != nil {
		t.Fatal(err)
	}

	select {
	case <-renewed:
	case <-time.After(10 * time.Second):
		t.Fatalf("renewal was abandoned after %d attempt(s), want a retry", attempts.Load())
	}
}

// The lifetime watcher exits on the first renewal error, so a transient one
// must not end renewal for the rest of the process lifetime.
func TestRenewalResumesAfterTheWatcherFails(t *testing.T) {
	var attempts atomic.Int32
	resumed := make(chan struct{})
	t.Setenv("BAO_MAX_RETRIES", "0") // exercise our retry, not the api client's
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		// The probe hands a renewable lease to the watcher, whose own renewal
		// then fails.
		if attempts.Add(1) == 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "test-token",
				"lease_duration": 3600,
				"renewable":      true,
			},
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
		if attempts.Load() > 2 {
			select {
			case <-resumed:
			default:
				close(resumed)
			}
		}
	})
	handleLookupSelf(t, mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := New(ctx, tokenConfig(t, srv), testLogger()); err != nil {
		t.Fatal(err)
	}

	select {
	case <-resumed:
	case <-time.After(10 * time.Second):
		t.Fatalf("renewal was abandoned after %d attempt(s), want it to resume", attempts.Load())
	}
}

// Re-authenticating on a renewal failure must back off. The login itself
// succeeds, so nothing else rate-limits the loop, and every pass mints a token.
func TestRenewalFailureDoesNotSpinOnRelogin(t *testing.T) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		logins.Add(1)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "approle-token",
				"lease_duration": 3600,
				"renewable":      true,
			},
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := New(ctx, approleConfig(t, srv, "role", "secret"), testLogger()); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)
	// One login at startup, then one per backoff step: 1s and 2s.
	if n := logins.Load(); n > 4 {
		t.Errorf("%d logins in 2s, want the retry loop to back off", n)
	}
}

// syncBuffer collects log output written from the renewal goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// renewSelfLog runs a client against a renew-self that answers with status,
// waits for want to be logged, and returns the log. Lookup-self accepts any
// token, renewability is the probe's to decide.
func renewSelfLog(t *testing.T, status int, message, want string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]any{"errors": []string{message}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	handleLookupSelf(t, mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var logs syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := New(ctx, tokenConfig(t, srv), slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if out := logs.String(); strings.Contains(out, want) {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("renewal never logged %q, got %q", want, logs.String())
	return ""
}

// A rejected token and one that merely cannot be renewed are both definitive,
// but only the first is a problem worth reporting as one.
func TestStaticTokenRejectionIsNotConfusedWithNonRenewable(t *testing.T) {
	rejected := renewSelfLog(t, http.StatusForbidden, "permission denied", "rejected the token")
	if !strings.Contains(rejected, "level=ERROR") {
		t.Errorf("403 logged as %q, want an error about a rejected token", rejected)
	}

	notRenewable := renewSelfLog(t, http.StatusBadRequest, "lease is not renewable", "will not be auto-renewed")
	if !strings.Contains(notRenewable, "level=INFO") {
		t.Errorf("400 logged as %q, want the non-renewable notice", notRenewable)
	}
}

// A reload keeps a working client, so CheckToken treats an unanswerable
// lookup as a refusal, while methods that logged in have nothing to check.
func TestCheckToken(t *testing.T) {
	srv := fakeBao(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client, err := New(ctx, tokenConfig(t, srv), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckToken(ctx); err != nil {
		t.Errorf("CheckToken with a valid token failed: %v", err)
	}

	approle, err := New(ctx, approleConfig(t, srv, "my-role", "my-secret"), testLogger())
	if err != nil {
		t.Fatal(err)
	}

	srv.Close()
	if err := client.CheckToken(ctx); err == nil {
		t.Error("CheckToken answered nothing against a closed server, want error")
	}
	if err := approle.CheckToken(ctx); err != nil {
		t.Errorf("CheckToken checked a login method: %v", err)
	}
}

// The daemon must come up while OpenBao is unreachable and serve once it
// returns, so an unanswered token check only logs.
func TestTokenAuthStartsDuringAnOutage(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listens, every request fails to connect

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_TOKEN", "test-token")
	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthToken

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := New(ctx, cfg, testLogger()); err != nil {
		t.Fatalf("New failed during an outage: %v", err)
	}
}

// A rejected token must fail authentication rather than report success and
// 403 on every later read, which is what lets a reload with a bad rotated
// token_file keep the previous client serving.
func TestTokenAuthChecksTheToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := New(context.Background(), tokenConfig(t, srv), testLogger())
	if err == nil || !strings.Contains(err.Error(), "checking the OpenBao token") {
		t.Errorf("err = %v, want the token check to fail authentication", err)
	}
}

func TestMissingToken(t *testing.T) {
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_TOKEN", "")

	var cfg config.OpenBao
	cfg.Auth.Method = config.AuthToken

	_, err := New(context.Background(), cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "no OpenBao token") {
		t.Errorf("err = %v, want missing-token error", err)
	}
}
