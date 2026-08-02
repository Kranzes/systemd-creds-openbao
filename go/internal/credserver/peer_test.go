package credserver

import (
	"net"
	"strings"
	"testing"
)

func unixAddr(name string) net.Addr {
	return &net.UnixAddr{Net: "unix", Name: name}
}

func TestParsePeer(t *testing.T) {
	tests := []struct {
		name    string
		addr    net.Addr
		want    Request
		wantErr bool
	}{
		{
			name: "example from systemd.exec(5)",
			addr: unixAddr("@adf9d86b6eda275e/unit/foobar.service/credx"),
			want: Request{Unit: "foobar.service", Credential: "credx"},
		},
		{
			name: "templated unit",
			addr: unixAddr("@1/unit/getty@tty1.service/agetty.password"),
			want: Request{Unit: "getty@tty1.service", Credential: "agetty.password"},
		},
		{
			name:    "pathname socket peer",
			addr:    unixAddr("/run/foo.sock"),
			wantErr: true,
		},
		{
			name:    "unbound peer",
			addr:    unixAddr(""),
			wantErr: true,
		},
		{
			name:    "missing unit marker",
			addr:    unixAddr("@adf9d86b6eda275e/foobar.service/credx"),
			wantErr: true,
		},
		{
			name:    "missing credential",
			addr:    unixAddr("@adf9d86b6eda275e/unit/foobar.service"),
			wantErr: true,
		},
		{
			name:    "empty credential",
			addr:    unixAddr("@adf9d86b6eda275e/unit/foobar.service/"),
			wantErr: true,
		},
		{
			name:    "empty unit",
			addr:    unixAddr("@adf9d86b6eda275e/unit//credx"),
			wantErr: true,
		},
		{
			name:    "not a unix address",
			addr:    &net.TCPAddr{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePeer(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePeer(%q) = %+v, want error", tt.addr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePeer(%q): %v", tt.addr, err)
			}
			if got != tt.want {
				t.Errorf("ParsePeer(%q) = %+v, want %+v", tt.addr, got, tt.want)
			}
		})
	}
}

// FuzzParsePeer holds ParsePeer to what everything downstream assumes about
// an accepted request: globs are matched against whole names and placeholder
// values join path segments, so neither part may be empty or contain a
// slash, and both must be exactly what the peer address encodes.
func FuzzParsePeer(f *testing.F) {
	f.Add("@adf9d86b6eda275e/unit/foobar.service/credx")
	f.Add("@1/unit/getty@tty1.service/agetty.password")
	f.Add("@x/unit/a/unit/b")
	f.Add("@/unit//")
	f.Add("/run/foo.sock")
	f.Add("")

	f.Fuzz(func(t *testing.T, name string) {
		req, err := ParsePeer(unixAddr(name))
		if err != nil {
			return
		}

		if req.Unit == "" || strings.Contains(req.Unit, "/") {
			t.Errorf("ParsePeer(%q) returned unit %q", name, req.Unit)
		}
		if req.Credential == "" || strings.Contains(req.Credential, "/") {
			t.Errorf("ParsePeer(%q) returned credential ID %q", name, req.Credential)
		}

		trimmed, ok := strings.CutPrefix(name, "@")
		if !ok {
			t.Fatalf("ParsePeer(%q) accepted an address outside the abstract namespace", name)
		}
		_, rest, ok := strings.Cut(trimmed, "/unit/")
		if !ok {
			t.Fatalf("ParsePeer(%q) accepted an address without a unit marker", name)
		}
		if want := req.Unit + "/" + req.Credential; rest != want {
			t.Errorf("ParsePeer(%q) = %+v, but the address encodes %q", name, req, rest)
		}
	})
}
