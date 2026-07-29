package credserver

import (
	"net"
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
