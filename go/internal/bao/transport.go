package bao

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// responseSizeMax limits the body of an OpenBao response. The client library
// buffers a whole response before anything looks at its size, and parsing tees
// it into a second buffer, so without a limit one read of a hostile or
// misconfigured server turns into gigabytes of heap. The daemon can serve at
// most 1 MiB (credserver.CredentialSizeMax, systemd's credential size limit).
// The rest is room for the JSON envelope and the other fields of the same
// secret.
const responseSizeMax = 4 * 1024 * 1024

// guardTransport caps the body of every OpenBao response and refuses a
// redirect away from https.
type guardTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if err := checkDowngrade(req, resp); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	if resp.ContentLength > t.limit {
		_ = resp.Body.Close()
		return nil, &responseTooLargeError{size: resp.ContentLength, limit: t.limit}
	}
	// One byte of slack, so a body of exactly the limit still reads to EOF.
	resp.Body = &limitBody{body: resp.Body, left: t.limit + 1, limit: t.limit}
	return resp, nil
}

// checkDowngrade refuses a redirect taking an https request to a plaintext
// address, which would put BAO_TOKEN and login bodies in the clear. The client
// library refuses it too. Checking it here makes it testable.
func checkDowngrade(req *http.Request, resp *http.Response) error {
	if req.URL.Scheme != "https" {
		return nil
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil
	}
	// A Location with no scheme is relative and stays on https, and one that
	// does not parse leads nowhere the library can follow.
	if loc, err := url.Parse(resp.Header.Get("Location")); err == nil &&
		loc.Scheme != "" && loc.Scheme != "https" {
		return &protocolDowngradeError{to: loc.Scheme}
	}
	return nil
}

// protocolDowngradeError reports a redirect away from https. It has a type so
// retryable can treat it as final. No retry fixes an address that answers with
// one, so the startup fails instead of backing off forever.
type protocolDowngradeError struct {
	to string // the scheme the redirect pointed at
}

func (e *protocolDowngradeError) Error() string {
	return fmt.Sprintf("refusing a redirect from https to %s, which would send the token in the clear", e.to)
}

// responseTooLargeError reports a response over responseSizeMax. It carries a
// type so retryable can pick it out of the *url.Error net/http wraps around a
// RoundTrip failure. A secret does not shrink on retry, so classifying it as
// transient would retry it forever and, with serve_stale_for set, keep the
// real cause out of the journal behind the stale-data warning.
type responseTooLargeError struct {
	size  int64 // 0 when only discovered while reading the body
	limit int64
}

func (e *responseTooLargeError) Error() string {
	if e.size > 0 {
		return fmt.Sprintf("response is %d bytes, over the %d byte limit", e.size, e.limit)
	}
	return fmt.Sprintf("response exceeds the %d byte limit", e.limit)
}

// limitBody fails an oversized read rather than truncating it, so the caller
// gets an error instead of a body that parses into a partial secret.
type limitBody struct {
	body  io.ReadCloser
	left  int64
	limit int64
}

func (b *limitBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, &responseTooLargeError{limit: b.limit}
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.body.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *limitBody) Close() error { return b.body.Close() }
