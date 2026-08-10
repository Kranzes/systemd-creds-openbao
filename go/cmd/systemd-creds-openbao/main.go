// Command systemd-creds-openbao serves secrets from OpenBao to systemd
// services as credentials, over the AF_UNIX protocol behind LoadCredential=.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/coreos/go-systemd/v22/journal"
	slogjournal "github.com/systemd/slog-journal"

	"github.com/kranzes/systemd-creds-openbao/go/internal/bao"
	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
	"github.com/kranzes/systemd-creds-openbao/go/internal/policy"
	"github.com/kranzes/systemd-creds-openbao/go/internal/secrets"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// reloadTimeout limits the OpenBao login a reload performs. The manager blocks
// on the READY=1 that ends a reload, so without it an OpenBao outage would
// take down a daemon that is serving fine.
const reloadTimeout = 30 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	var (
		configPath  = flag.String("config", "/etc/systemd-creds-openbao/config.toml", "path to the configuration file")
		checkOnly   = flag.Bool("check", false, "validate the configuration")
		printPolicy = flag.Bool("print-policy", false, "print an OpenBao policy covering the configured rules")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, or error")
		showVersion = flag.Bool("version", false, "print the version")
	)
	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q (the configuration file is set with -config)\n", flag.Arg(0))
		return 2
	}

	if *showVersion {
		fmt.Println("systemd-creds-openbao", version)
		return 0
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -log-level %q\n", *logLevel)
		return 2
	}
	log := newLogger(level)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Error("cannot load configuration", "PATH", *configPath, "ERROR", err)
		return 1
	}
	if *printPolicy {
		// A policy granting nothing would revoke the access the daemon has
		// now, so refuse to print one.
		if len(cfg.Credentials) == 0 {
			log.Error("no [[credentials]] rules are configured, so there is nothing to grant", "PATH", *configPath)
			return 1
		}
		fmt.Print(policy.Generate(cfg.Credentials))
		return 0
	}
	if *checkOnly {
		fmt.Println("configuration OK")
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)

	// Adopting the sockets first fails a misconfigured socket unit right away,
	// since logging in retries a transient failure indefinitely.
	listeners, err := listen()
	if err != nil {
		log.Error("failed to listen", "ERROR", err)
		return 1
	}

	// The client's context governs its token renewal. A reload cancels it.
	clientCtx, stopClient := context.WithCancel(ctx)
	client, err := bao.New(clientCtx, cfg.OpenBao, log)
	if err != nil {
		stopClient()
		log.Error("failed to set up OpenBao client", "ERROR", err)
		return 1
	}

	// The cache outlives reloads, so responses fetched before a SIGHUP still
	// cover an outage after it. Its sweep runs under ctx, not clientCtx, for
	// the same reason.
	cache := bao.NewStaleCache(ctx, client, cfg.OpenBao.ServeStaleFor, log)

	srv := credserver.New(
		secrets.NewResolver(cfg.Credentials, cache),
		log,
		cfg.Server.ConnectionTimeout,
	)
	svc := &service{
		configPath: *configPath,
		log:        log,
		srv:        srv,
		cache:      cache,
		cfg:        cfg,
		stopClient: stopClient,
	}
	defer func() { svc.stopClient() }()

	serveClosed := make(chan struct{}, len(listeners))
	for _, l := range listeners {
		log.Info("listening", "ADDRESS", l.Addr())
		go func() {
			// Serve retries accept errors and returns nil only once the
			// listener is closed.
			_ = srv.Serve(l)
			serveClosed <- struct{}{}
		}()
	}

	svc.notifyReady()
	defer notify(log, daemon.SdNotifyStopping)

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down on signal")
			return 0
		case <-serveClosed:
			// Nothing in the daemon closes a listener. The sockets are
			// systemd's. Whatever did leaves requests queueing unanswered,
			// so fail: the restart re-adopts the socket unit's fd.
			log.Error("listener closed unexpectedly")
			return 1
		case <-srv.StatsUpdates():
			notify(log, svc.status())
		case <-reload:
			svc.reload(ctx)
		}
	}
}

// service holds the state a configuration reload replaces.
type service struct {
	configPath string
	log        *slog.Logger
	srv        *credserver.Server
	cache      *bao.StaleCache

	cfg        *config.Config
	stopClient context.CancelFunc
}

// reload re-reads the configuration file and re-authenticates to OpenBao,
// picking up rotated credential files (token_file, secret_id_file, jwt_file).
// A reload that cannot be completed is abandoned, leaving the previous
// configuration serving.
func (s *service) reload(ctx context.Context) {
	// The next READY=1 ends the reload, success or not.
	notify(s.log, daemon.SdNotifyReloading+"\n"+daemon.SdNotifyMonotonicUsec())
	defer s.notifyReady()

	s.log.Info("reloading configuration", "PATH", s.configPath)

	cfg, err := loadConfig(s.configPath)
	if err != nil {
		s.log.Error("reload failed, keeping the previous configuration", "PATH", s.configPath, "ERROR", err)
		return
	}

	clientCtx, stopClient := context.WithCancel(ctx)
	// bao.New retries a failing login for as long as its context lives, so
	// cancelling the context is what makes it give up.
	giveUp := time.AfterFunc(reloadTimeout, stopClient)
	client, err := bao.New(clientCtx, cfg.OpenBao, s.log)
	if !giveUp.Stop() {
		err = fmt.Errorf("authenticating to OpenBao took longer than %s", reloadTimeout)
	}
	if err != nil {
		stopClient()
		s.log.Error("reload failed, keeping the previous configuration", "ERROR", err)
		return
	}

	// Swap before stopping the previous client: in-flight requests still
	// hold it, and its token has to stay valid for them.
	s.cache.Swap(client, cfg.OpenBao.ServeStaleFor)
	s.srv.Reload(secrets.NewResolver(cfg.Credentials, s.cache), cfg.Server.ConnectionTimeout)
	s.stopClient()
	s.stopClient, s.cfg = stopClient, cfg
	s.log.Info("configuration reloaded", "RULES", len(cfg.Credentials))
}

// status summarizes for `systemctl status` what is in effect and how many
// requests have been served and refused since the daemon started.
func (s *service) status() string {
	served, refused := s.srv.Stats()
	return fmt.Sprintf("STATUS=serving %d credential rules, authenticated with %s; %d served, %d refused",
		len(s.cfg.Credentials), s.cfg.OpenBao.Auth.Method, served, refused)
}

// notifyReady reports readiness along with the status summary.
func (s *service) notifyReady() {
	notify(s.log, daemon.SdNotifyReady+"\n"+s.status())
}

// notify sends a state update to the service manager. It does nothing when
// NOTIFY_SOCKET is unset.
func notify(log *slog.Logger, state string) {
	if _, err := daemon.SdNotify(false, state); err != nil {
		log.Warn("failed to notify the service manager", "ERROR", err)
	}
}

func loadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return config.Parse(data)
}

// newLogger writes native journal entries when stderr is the journal stream,
// and text to stderr otherwise. Attr keys reach the journal verbatim, and
// journald silently drops any field not matching ^[A-Z_][A-Z0-9_]*$, so
// callsites use keys like "ERROR" and "RETRY_IN".
func newLogger(level slog.Level) *slog.Logger {
	if ok, err := journal.StderrIsJournalStream(); err == nil && ok {
		h, err := slogjournal.NewHandler(&slogjournal.Options{Level: level})
		if err == nil {
			return slog.New(h)
		}
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// listen returns the sockets systemd passed in. The socket unit owns their
// setup, so the daemon never opens one itself.
func listen() ([]net.Listener, error) {
	listeners, err := activation.Listeners()
	if err != nil {
		return nil, fmt.Errorf("checking for socket activation: %w", err)
	}
	if len(listeners) == 0 {
		return nil, errors.New("no sockets received (start via systemd-creds-openbao.socket)")
	}
	for i, l := range listeners {
		if l == nil {
			return nil, fmt.Errorf("activation file descriptor %d is not a stream socket (the socket unit needs ListenStream= with Accept=no)", i+3)
		}
		// The credential protocol authenticates via AF_UNIX peer names, so
		// any other socket could only ever refuse requests. Datagram and
		// seqpacket sockets also arrive as a *net.UnixListener and fail on
		// every accept, so match on the network, not the Go type.
		if l.Addr().Network() != "unix" {
			return nil, fmt.Errorf("listener %s is not an AF_UNIX stream socket (the socket unit needs ListenStream=, not ListenDatagram= or ListenSequentialPacket=)", l.Addr())
		}
	}
	return listeners, nil
}
