// Command opendrm is the opendrm server and CLI.
//
//	opendrm serve  -config opendrm.json
//	opendrm keys create -config opendrm.json -title ip-c3 -track 1080p -policy paid-members -hardware
//	opendrm keys list   -config opendrm.json
//	opendrm token  -config opendrm.json -user user_8812 -title ip-c3 -claim plan=paid
//	opendrm version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/opendrm-org/opendrm/internal/config"
	"github.com/opendrm-org/opendrm/internal/keystore"
	"github.com/opendrm-org/opendrm/internal/license"
	"github.com/opendrm-org/opendrm/internal/session"
	"github.com/opendrm-org/opendrm/internal/token"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "keys":
		err = keys(os.Args[2:])
	case "token":
		err = mintToken(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("opendrm", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "opendrm: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "opendrm:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `opendrm: self-hosted DRM. No toll per viewer.

Commands:
  serve         run the license server
  keys create   create a content key for a title track
  keys list     list content keys (never prints the keys themselves)
  token         mint a test playback token
  version       print the version

Run "opendrm <command> -h" for flags.
`)
}

func loadStore(cfgPath string) (*config.Config, *keystore.FileStore, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	mk, created, err := keystore.LoadOrCreateLocalMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return nil, nil, err
	}
	if created {
		fmt.Fprintf(os.Stderr, "created master key %s at %s. Back it up: without it, content keys cannot be recovered.\n", mk.ID(), cfg.MasterKeyFile)
	}
	store, err := keystore.OpenFileStore(cfg.KeysFile, mk)
	return cfg, store, err
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "opendrm.json", "path to opendrm.json")
	fs.Parse(args)

	cfg, store, err := loadStore(*cfgPath)
	if err != nil {
		return err
	}
	secret, err := cfg.TokenSecret()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	svc := &license.Service{
		Keys:           store,
		Policies:       cfg.PolicyMap(),
		TokenSecret:    secret,
		TokenLeeway:    time.Duration(cfg.TokenLeewaySeconds) * time.Second,
		Streams:        session.NewTracker(time.Duration(cfg.StreamLeaseSeconds) * time.Second),
		Revoked:        session.NewRevocations(),
		CountryHeader:  cfg.CountryHeader,
		AllowedOrigins: cfg.AllowedOrigins,
		Now:            time.Now,
		Log:            log,
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("opendrm listening", "addr", cfg.Listen, "version", version, "policies", len(cfg.Policies))

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func keys(args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: opendrm keys create|list [flags]`)
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("keys create", flag.ExitOnError)
		cfgPath := fs.String("config", "opendrm.json", "path to opendrm.json")
		title := fs.String("title", "", "title id, e.g. ip-c3 (required)")
		track := fs.String("track", "all", "which tracks this key encrypts, e.g. sd, 1080p, audio")
		pol := fs.String("policy", "", "policy name from opendrm.json (required)")
		hw := fs.Bool("hardware", false, "only release this key to hardware-backed DRM (Widevine L1, FairPlay)")
		fs.Parse(args[1:])
		if *title == "" || *pol == "" {
			return errors.New("-title and -policy are required")
		}
		cfg, store, err := loadStore(*cfgPath)
		if err != nil {
			return err
		}
		if _, ok := cfg.PolicyMap()[*pol]; !ok {
			return fmt.Errorf("no policy named %q in %s", *pol, *cfgPath)
		}
		ck, err := store.Generate(*title, *track, *pol, *hw)
		if err != nil {
			return err
		}
		fmt.Println(ck.KID.String())
		return nil
	case "list":
		fs := flag.NewFlagSet("keys list", flag.ExitOnError)
		cfgPath := fs.String("config", "opendrm.json", "path to opendrm.json")
		fs.Parse(args[1:])
		_, store, err := loadStore(*cfgPath)
		if err != nil {
			return err
		}
		list, err := store.List()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KID\tTITLE\tTRACK\tPOLICY\tHARDWARE\tCREATED")
		for _, ck := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\n", ck.KID, ck.Title, ck.Track, ck.Policy, ck.RequiresHardware, ck.CreatedAt.Format(time.RFC3339))
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown keys command %q", args[0])
	}
}

type claimFlags map[string]string

func (c claimFlags) String() string { return fmt.Sprint(map[string]string(c)) }
func (c claimFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("claim must be name=value, got %q", v)
	}
	c[k] = val
	return nil
}

func mintToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	cfgPath := fs.String("config", "opendrm.json", "path to opendrm.json (for the secret's env var name)")
	user := fs.String("user", "", "viewer id (required)")
	title := fs.String("title", "", "title id (required)")
	device := fs.String("device", "cli", "device id")
	ttl := fs.Duration("ttl", time.Minute, "token lifetime")
	claims := claimFlags{}
	fs.Var(claims, "claim", "extra claim name=value, repeatable (e.g. -claim plan=paid)")
	fs.Parse(args)
	if *user == "" || *title == "" {
		return errors.New("-user and -title are required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	secret, err := cfg.TokenSecret()
	if err != nil {
		return err
	}
	now := time.Now()
	c := map[string]any{"sub": *user, "title": *title, "device": *device, "iat": now.Unix(), "exp": now.Add(*ttl).Unix()}
	for k, v := range claims {
		c[k] = v
	}
	tok, err := token.Sign(secret, c)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
