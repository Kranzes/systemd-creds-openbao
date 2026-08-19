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
	"runtime/debug"
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

// version is set at build time via -ldflags "-X main.version=...". Builds
// without the injection report what the toolchain stamped instead. For
// `go install module@version` that is the module version, for a checkout
// build the commit, since tag stamping skips modules in a subdirectory.
var version string

func resolvedVersion() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", ""
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if bi.Main.Version == "(devel)" && rev != "" {
		return rev[:min(12, len(rev))] + dirty
	}
	return bi.Main.Version
}

// reloadTimeout limits the OpenBao authentication a reload performs. The
// manager blocks on the READY=1 that ends a reload, so without it an OpenBao
// outage would take down a daemon that is serving fine.
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
		resolveReq  = flag.Bool("resolve", false, "print which rule and secret serve a request (usage: -resolve UNIT CREDENTIAL)")
		showVersion = flag.Bool("version", false, "print the version")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("systemd-creds-openbao", resolvedVersion())
		return 0
	}

	if *resolveReq {
		if flag.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "-resolve takes exactly two arguments: UNIT CREDENTIAL")
			return 2
		}
	} else if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q (the configuration file is set with -config)\n", flag.Arg(0))
		return 2
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
	if *resolveReq {
		req, err := credserver.NewRequest(flag.Arg(0), flag.Arg(1))
		if err != nil {
			log.Error("request refused", "ERROR", err)
			return 1
		}
		plan, err := secrets.NewResolver(cfg.Credentials, nil).Plan(req)
		if err != nil {
			log.Error("request refused", "ERROR", err)
			return 1
		}
		fmt.Println(describePlan(plan))
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
	// since authenticating retries a transient failure indefinitely.
	listeners, err := listen()
	if err != nil {
		log.Error("failed to listen", "ERROR", err)
		return 1
	}

	cfg, client, stopClient, err := authenticate(ctx, log, *configPath, cfg)
	if err != nil {
		if ctx.Err() != nil {
			log.Info("shutting down on signal")
			return 0
		}
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
		client:     client,
		stopClient: stopClient,
	}
	defer func() {
		svc.stopClient()
		// Shutdown cuts in-flight requests off anyway, so the token can go
		// right away instead of staying live until its TTL.
		svc.client.RevokeSelf(context.WithoutCancel(ctx))
	}()

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

	// Pinging from this loop makes the watchdog prove the loop handling
	// reloads and signals is alive, not just the process.
	watchdog := watchdogTicks(log)

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down on signal")
			return 0
		case <-watchdog:
			notify(log, daemon.SdNotifyWatchdog)
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
	client     *bao.Client
	stopClient context.CancelFunc
}

// reload re-reads the configuration file and re-authenticates to OpenBao,
// picking up rotated credential files (token_file, secret_id_file, jwt_file).
// A reload that cannot be completed is abandoned, leaving the previous
// configuration serving.
func (s *service) reload(ctx context.Context) {
	// The next READY=1 ends the reload, success or not. A reload blocks the
	// loop's watchdog ticks for up to reloadTimeout, so both of its edges
	// reset the watchdog instead, here and in notifyReady.
	notify(s.log, daemon.SdNotifyReloading+"\n"+daemon.SdNotifyMonotonicUsec()+"\n"+daemon.SdNotifyWatchdog)
	defer s.notifyReady()

	s.log.Info("reloading configuration", "PATH", s.configPath)

	cfg, err := loadConfig(s.configPath)
	if err != nil {
		s.log.Error("reload failed, keeping the previous configuration", "PATH", s.configPath, "ERROR", err)
		return
	}

	clientCtx, stopClient := context.WithCancel(ctx)
	// bao.New retries a failing authentication for as long as its context
	// lives, so cancelling the context is what makes it give up.
	giveUp := time.AfterFunc(reloadTimeout, stopClient)
	notify(s.log, "STATUS=authenticating with "+cfg.OpenBao.Auth.Method)
	client, err := bao.New(clientCtx, cfg.OpenBao, s.log, retryStatus(s.log))
	if !giveUp.Stop() {
		// The timer fired, so clientCtx is canceled and even a login that
		// made it produced a client whose renewal is already stopping. A
		// definitive failure that lost the race keeps its own message.
		switch {
		case err == nil:
			client.RevokeSelf(context.WithoutCancel(ctx))
			err = fmt.Errorf("authentication finished only as the reload gave up after %s", reloadTimeout)
		case errors.Is(err, context.Canceled):
			err = fmt.Errorf("authenticating to OpenBao took longer than %s", reloadTimeout)
		}
	}
	if err != nil {
		stopClient()
		s.log.Error("reload failed, keeping the previous configuration", "ERROR", err)
		return
	}

	// The swaps are adjacent but not atomic, a request landing between them
	// pairs the new rules with the old client. Both precede stopping the
	// previous client, since in-flight requests still need its token.
	s.srv.Reload(secrets.NewResolver(cfg.Credentials, s.cache), cfg.Server.ConnectionTimeout)
	s.cache.Swap(client, cfg.OpenBao.ServeStaleFor)
	s.stopClient()
	// The old token stays valid until every request that can still hold the
	// old client has finished, then it is revoked rather than left live
	// until its TTL. A swap-window request runs under the new timeout, so
	// the wait covers the larger of the two, plus the ProbeTimeout that a
	// last-moment 403 may still spend on its token check.
	old, revokeCtx := s.client, context.WithoutCancel(ctx)
	time.AfterFunc(max(s.cfg.Server.ConnectionTimeout, cfg.Server.ConnectionTimeout)+bao.ProbeTimeout, func() {
		old.RevokeSelf(revokeCtx)
	})
	s.client, s.stopClient, s.cfg = client, stopClient, cfg
	s.log.Info("configuration reloaded", "RULES", len(cfg.Credentials))
}

// status summarizes for `systemctl status` what is in effect and how many
// requests have been served and refused since the daemon started. A request
// answered from the stale cache counts as served, and once there has been
// one the line says how many, so an outage the cache covered shows there and
// not only in the journal.
func (s *service) status() string {
	served, refused := s.srv.Stats()
	stale := ""
	if n := s.cache.StaleServed(); n > 0 {
		stale = fmt.Sprintf(" (%d stale)", n)
	}
	return fmt.Sprintf("STATUS=serving %d credential rules, authenticated with %s; %d served%s, %d refused",
		len(s.cfg.Credentials), s.cfg.OpenBao.Auth.Method, served, stale, refused)
}

// notifyReady reports readiness along with the status summary. The watchdog
// reset makes it the closing edge of a reload. The restart counter is kept
// across automatic restarts, so resetting it here confines the unit's growing
// restart delay to consecutive failed starts, and a crash long after a
// rejected login is retried at the first step again.
func (s *service) notifyReady() {
	notify(s.log, daemon.SdNotifyReady+"\n"+s.status()+"\n"+daemon.SdNotifyWatchdog+"\nRESTART_RESET=1")
}

// watchdogTicks returns ticks at half the WatchdogSec= interval the service
// manager configured, or a nil channel, never ready, when it set none.
func watchdogTicks(log *slog.Logger) <-chan time.Time {
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		log.Warn("cannot read the watchdog configuration", "ERROR", err)
		return nil
	}
	if interval == 0 {
		return nil
	}
	// A reload blocks the loop feeding the watchdog while it authenticates
	// for up to reloadTimeout and may spend RevokeTimeout more discarding a
	// login that the race threw away, pinging only at the edges. An interval
	// inside that time gets the daemon killed mid-reload.
	if limit := reloadTimeout + bao.RevokeTimeout; interval <= limit {
		log.Warn("WatchdogSec= is not above what a slow reload can take, which trips the watchdog",
			"WATCHDOG_SEC", interval, "RELOAD_LIMIT", limit)
	}
	return time.Tick(interval / 2)
}

// notify sends a state update to the service manager. It does nothing when
// NOTIFY_SOCKET is unset.
func notify(log *slog.Logger, state string) {
	if _, err := daemon.SdNotify(false, state); err != nil {
		log.Warn("failed to notify the service manager", "ERROR", err)
	}
}

// authenticate builds the OpenBao client at startup, waiting out an outage.
// The client's context governs its token renewal, and a reload cancels it.
// The wait can outlast a reload, which the service manager folds into the
// pending start without a signal, so once the client is up the configuration
// is read again, and when its [openbao] section changed the client is built
// again from that. It returns the configuration the client belongs to.
func authenticate(ctx context.Context, log *slog.Logger, configPath string, cfg *config.Config) (*config.Config, *bao.Client, context.CancelFunc, error) {
	for {
		clientCtx, stopClient := context.WithCancel(ctx)
		notify(log, "STATUS=authenticating with "+cfg.OpenBao.Auth.Method)
		client, err := bao.New(clientCtx, cfg.OpenBao, log, retryStatus(log))
		if err != nil {
			stopClient()
			return nil, nil, nil, err
		}
		fresh, err := loadConfig(configPath)
		if err != nil {
			log.Warn("configuration does not load after authenticating, keeping the one read at startup", "PATH", configPath, "ERROR", err)
			return cfg, client, stopClient, nil
		}
		if fresh.OpenBao == cfg.OpenBao {
			return fresh, client, stopClient, nil
		}
		log.Info("configuration changed while authenticating, authenticating again", "PATH", configPath)
		stopClient()
		client.RevokeSelf(context.WithoutCancel(ctx))
		cfg = fresh
	}
}

// retryStatus shows each authentication attempt that the client is waiting to
// retry as the unit's status, so `systemctl status` says why the service is
// still activating, or what a reload is stuck on.
func retryStatus(log *slog.Logger) bao.Option {
	return bao.ReportRetries(func(line string) {
		notify(log, "STATUS="+line)
	})
}

// describePlan renders a resolution for -resolve. The location is what the
// journal's SECRET_PATH field carries for the same request.
func describePlan(p secrets.Plan) string {
	head := fmt.Sprintf("rule %d (unit = %q, credential = %q) reads %q",
		p.RuleIndex, p.Rule.Unit, p.Rule.Credential, p.Ref.Location())
	switch {
	case p.Rule.Format == config.FormatJSON:
		return head + ", all fields as JSON"
	case p.Rule.Encoding == config.EncodingBase64:
		return fmt.Sprintf("%s field %q, base64-decoded", head, p.Field)
	default:
		return fmt.Sprintf("%s field %q", head, p.Field)
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
