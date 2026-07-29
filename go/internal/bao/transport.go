package bao

import (
	"fmt"
	"io"
	"net/http"

	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
)

// responseSizeMax bounds the body of an OpenBao response. The client library
// buffers a whole response before anything looks at its size, and parsing tees
// it into a second buffer, so without a limit one read of a hostile or
// misconfigured server turns into gigabytes of heap. The daemon can serve at
// most CredentialSizeMax; the rest is room for the JSON envelope and the other
// fields of the same secret.
const responseSizeMax = 4 * credserver.CredentialSizeMax

// limitTransport caps the response body of every OpenBao request.
type limitTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > t.limit {
		resp.Body.Close()
		return nil, fmt.Errorf("response is %d bytes, over the %d byte limit", resp.ContentLength, t.limit)
	}
	// One byte of slack, so a body of exactly the limit still reads to EOF.
	resp.Body = &limitBody{body: resp.Body, left: t.limit + 1, limit: t.limit}
	return resp, nil
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
		return 0, fmt.Errorf("response exceeds the %d byte limit", b.limit)
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.body.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *limitBody) Close() error { return b.body.Close() }
