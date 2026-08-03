// Package bao wraps the OpenBao client library with the authentication and
// secret reads the daemon needs.
package bao

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

// Client is an authenticated OpenBao API client. All methods are safe for
// concurrent use.
type Client struct {
	api  *api.Client
	auth config.Auth
	log  *slog.Logger
}

// New builds a client, authenticates it, and keeps the token fresh in the
// background until ctx is canceled. The connection (address, TLS, namespace,
// timeout) comes only from the BAO_*/VAULT_* environment variables.
func New(ctx context.Context, cfg config.OpenBao, log *slog.Logger) (*Client, error) {
	apiCfg := api.DefaultConfig()
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("reading client environment: %w", apiCfg.Error)
	}
	ac, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("creating OpenBao client: %w", err)
	}
	// The library type-asserts Transport to *http.Transport while it configures
	// TLS, the proxy, and unix:// addresses, all of which are done by the time
	// NewClient returns.
	apiCfg.HttpClient.Transport = &limitTransport{
		base:  apiCfg.HttpClient.Transport,
		limit: responseSizeMax,
	}

	c := &Client{api: ac, auth: cfg.Auth, log: log}
	if err := c.authenticate(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// ReadKV implements secrets.Reader.
func (c *Client) ReadKV(ctx context.Context, mount, secretPath string) (map[string]any, error) {
	secret, err := c.api.KVv2(mount).Get(ctx, secretPath)
	if err != nil {
		return nil, err
	}
	if secret.Data == nil {
		// A soft-deleted or destroyed version has an empty payload;
		// serving it would hand the unit a literal "null".
		return nil, errors.New("secret version is deleted or has no data")
	}
	return secret.Data, nil
}

// ReadRaw implements secrets.Reader.
func (c *Client) ReadRaw(ctx context.Context, apiPath string) (map[string]any, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, api.ErrSecretNotFound
	}
	return secret.Data, nil
}

// authenticate logs in and starts the goroutine that keeps the token fresh.
func (c *Client) authenticate(ctx context.Context) error {
	switch c.auth.Method {
	case config.AuthToken:
		token, err := valueOrFile("", c.auth.TokenFile, "token_file")
		if err != nil {
			return err
		}
		if token != "" {
			c.api.SetToken(token)
		}
		if c.api.Token() == "" {
			return errors.New("no OpenBao token: set openbao.auth.token_file")
		}
		go c.renewStaticToken(ctx)
		return nil

	case config.AuthAppRole, config.AuthCert, config.AuthJWT:
		secret, err := c.loginWithRetry(ctx, true)
		if err != nil {
			return fmt.Errorf("%s login: %w", c.auth.Method, err)
		}
		go c.manageTokenLifecycle(ctx, secret, true)
		return nil

	default:
		// Unreachable: config validation rejects unknown methods.
		return fmt.Errorf("unknown auth method %q", c.auth.Method)
	}
}

// loginWithRetry logs in with backoff, re-reading any credential files on
// every attempt so rotated credentials are picked up. failFast ends the loop
// on a definitive rejection, failing the unit at startup instead of retrying
// forever; without it a long-running daemon waits out a rotation. Transient
// failures back off in process rather than crash-looping the daemon into
// systemd's start limit.
func (c *Client) loginWithRetry(ctx context.Context, failFast bool) (*api.Secret, error) {
	return c.withRetry(ctx, "OpenBao login", failFast, func() (*api.Secret, error) {
		return c.login(ctx)
	})
}

// Retries and renewal failures share one backoff schedule.
const (
	backoffStart = time.Second
	backoffMax   = time.Minute
)

// withRetry calls do until it succeeds or ctx is canceled, backing off between
// attempts; with failFast a definitive rejection ends the loop instead.
func (c *Client) withRetry(ctx context.Context, what string, failFast bool, do func() (*api.Secret, error)) (*api.Secret, error) {
	backoff := backoffStart
	for {
		secret, err := do()
		if err == nil || (failFast && !retryable(err)) {
			return secret, err
		}
		c.log.Warn(what+" failed, retrying", "ERROR", err, "RETRY_IN", backoff)
		if !sleep(ctx, backoff) {
			return nil, ctx.Err()
		}
		backoff = min(backoff*2, backoffMax)
	}
}

// retryable reports whether err is transient (transport failure, 5xx,
// throttling) rather than a definitive rejection.
func retryable(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode >= http.StatusInternalServerError ||
			respErr.StatusCode == http.StatusTooManyRequests
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func (c *Client) login(ctx context.Context) (*api.Secret, error) {
	switch c.auth.Method {
	case config.AuthCert:
		return c.loginCert(ctx)
	case config.AuthJWT:
		return c.loginJWT(ctx)
	default:
		return c.loginAppRole(ctx)
	}
}

func (c *Client) loginAppRole(ctx context.Context) (*api.Secret, error) {
	roleID, err := valueOrFile(c.auth.RoleID, c.auth.RoleIDFile, "role_id_file")
	if err != nil {
		return nil, err
	}
	secretID, err := valueOrFile("", c.auth.SecretIDFile, "secret_id_file")
	if err != nil {
		return nil, err
	}

	secret, err := c.api.Logical().WriteWithContext(ctx, c.loginPath(), map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return nil, err
	}
	return c.setLoginToken(secret)
}

// loginCert authenticates with the TLS client certificate the connection
// already presents. The client library reads it when the client is built, so a
// reload picks up a rotated one.
func (c *Client) loginCert(ctx context.Context) (*api.Secret, error) {
	if api.ReadBaoVariable(api.EnvVaultClientCert) == "" &&
		api.ReadBaoVariable(api.EnvVaultClientCertBytes) == "" {
		return nil, errors.New("cert auth requires a TLS client certificate: set BAO_CLIENT_CERT and BAO_CLIENT_KEY")
	}
	data := map[string]any{}
	if c.auth.CertRole != "" {
		data["name"] = c.auth.CertRole
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, c.loginPath(), data)
	if err != nil {
		return nil, err
	}
	return c.setLoginToken(secret)
}

// loginJWT authenticates with the JWT read from jwt_file. The file is re-read
// on every attempt, so a token rotated on disk is picked up at
// re-authentication.
func (c *Client) loginJWT(ctx context.Context) (*api.Secret, error) {
	jwt, err := valueOrFile("", c.auth.JWTFile, "jwt_file")
	if err != nil {
		return nil, err
	}
	data := map[string]any{"jwt": jwt}
	if c.auth.JWTRole != "" {
		data["role"] = c.auth.JWTRole
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, c.loginPath(), data)
	if err != nil {
		return nil, err
	}
	return c.setLoginToken(secret)
}

func (c *Client) loginPath() string {
	return "auth/" + strings.Trim(c.auth.Mount, "/") + "/login"
}

func (c *Client) setLoginToken(secret *api.Secret) (*api.Secret, error) {
	token, err := secret.TokenID()
	if err != nil {
		return nil, fmt.Errorf("reading token from login response: %w", err)
	}
	if token == "" {
		return nil, errors.New("login response contains no token")
	}
	c.api.SetToken(token)
	c.log.Info("authenticated to OpenBao", "METHOD", c.auth.Method)
	return secret, nil
}

// renewStaticToken keeps a renewable configured token alive for as long as
// OpenBao permits. A static token cannot be re-acquired, so once renewal is
// exhausted the daemon serves until reads start failing.
func (c *Client) renewStaticToken(ctx context.Context) {
	// The first renewal runs at startup, so treating an unreachable OpenBao
	// as "not renewable" would drop renewal for the whole process lifetime.
	secret, err := c.withRetry(ctx, "renewing the OpenBao token", true, func() (*api.Secret, error) {
		return c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	})
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		// renew-self succeeds for any valid token, even one carrying no
		// default policy, so a 403 means the token itself was rejected.
		var respErr *api.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
			c.log.Error("OpenBao rejected the token: it is invalid or revoked", "ERROR", err)
			return
		}
		c.log.Info("token will not be auto-renewed", "REASON", err)
		return
	}
	c.manageTokenLifecycle(ctx, secret, false)
}

// manageTokenLifecycle renews the login token for as long as OpenBao permits
// and, with canRelogin, re-authenticates once renewal is exhausted.
func (c *Client) manageTokenLifecycle(ctx context.Context, secret *api.Secret, canRelogin bool) {
	backoff := backoffStart
	for {
		ttl, err := secret.TokenTTL()
		if err != nil || ttl <= 0 {
			return // non-expiring token; nothing to manage
		}

		var renewErr error
		if renewable, _ := secret.TokenIsRenewable(); renewable {
			if renewErr = c.renewUntilExpiry(ctx, secret); renewErr != nil {
				if ctx.Err() != nil {
					return
				}
				c.log.Warn("token renewal ended", "ERROR", renewErr)
			}
			// Nothing to renew, so wait the lease out with a margin and
			// re-authenticate instead.
		} else if !sleep(ctx, ttl-ttl/10) {
			return
		}
		// The watcher gives up on the first renewal error, so unlike a lease
		// run to exhaustion the token still has most of its life left. Back
		// off rather than spin on whatever failed, and prefer retrying the
		// renewal over minting a token per attempt.
		if renewErr != nil {
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, backoffMax)
		} else {
			backoff = backoffStart
		}
		if !canRelogin {
			if renewErr != nil && retryable(renewErr) {
				continue
			}
			c.log.Error("OpenBao token is about to expire and cannot be re-acquired; provide a fresh token and restart")
			return
		}
		next, err := c.loginWithRetry(ctx, false)
		if err != nil {
			return // ctx canceled
		}
		secret = next
	}
}

// renewUntilExpiry blocks while the token is being renewed and returns when it
// cannot be renewed any further, or when ctx is canceled.
func (c *Client) renewUntilExpiry(ctx context.Context, secret *api.Secret) error {
	watcher, err := c.api.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: secret,
		// The watcher's retry path leaves the sleep at zero, so a token it
		// cannot renew becomes a tight request loop for the rest of the
		// lease. Re-authenticating backs off instead.
		RenewBehavior: api.RenewBehaviorErrorOnErrors,
	})
	if err != nil {
		return fmt.Errorf("creating lifetime watcher: %w", err)
	}
	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-watcher.DoneCh():
			return err
		case renewal := <-watcher.RenewCh():
			// A renewal carries the new TTL under auth; the top-level
			// lease duration stays zero.
			ttl, _ := renewal.Secret.TokenTTL()
			c.log.Debug("renewed OpenBao token", "TTL", ttl)
		}
	}
}

// sleep waits for d, reporting false if ctx was canceled first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// valueOrFile returns the literal value, or the contents of file when one is
// configured; name is the config key used in error messages. The path may
// reference environment variables (${CREDENTIALS_DIRECTORY}/...).
func valueOrFile(literal, file, name string) (string, error) {
	if file == "" {
		return literal, nil
	}
	file, err := expandEnv(file)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", name, err)
	}
	if v := strings.TrimRight(string(data), "\r\n"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("reading %s: %s is empty", name, file)
}

// expandEnv is os.ExpandEnv, except that an unset variable is an error:
// "${CREDENTIALS_DIRECTORY}/token" outside a systemd unit must fail loudly,
// not become the unrelated path "/token".
func expandEnv(s string) (string, error) {
	var missing []string
	expanded := os.Expand(s, func(name string) string {
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("undefined environment variable %s in %q", strings.Join(missing, ", "), s)
	}
	return expanded, nil
}
