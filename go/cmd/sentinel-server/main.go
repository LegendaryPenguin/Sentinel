// Command sentinel-server serves one log over HTTP.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LegendaryPenguin/sentinel/logstore"
	"github.com/LegendaryPenguin/sentinel/service"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	path := flag.String("log", "sentinel.log", "path to the log file")
	noSync := flag.Bool("no-fsync", false,
		"skip fsync on append (benchmarks only: acknowledged entries are no longer durable)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	store, recovery, err := logstore.Open(*path, !*noSync)
	if err != nil {
		logger.Error("cannot open log", "path", *path, "error", err)
		// A corrupt log is a refusal to start, not a warning to serve
		// through. Coming up and answering queries from a log that failed its
		// integrity check is the one behaviour this project exists to make
		// impossible.
		os.Exit(1)
	}
	defer store.Close()

	logger.Info("log opened",
		"path", *path,
		"entries", recovery.EntriesLoaded,
		"fsync_per_append", !*noSync)
	if recovery.TailBytesDiscarded > 0 {
		// Worth saying loudly. The entry was never acknowledged and no root
		// ever contained it, so discarding it is correct — but it means the
		// previous process died mid-append.
		logger.Warn("discarded an incomplete trailing record; the previous process died mid-append",
			"bytes", recovery.TailBytesDiscarded)
	}
	if *noSync {
		logger.Warn("fsync is disabled: an acknowledged append may not survive a crash")
	}

	root, err := store.Root()
	if err != nil {
		logger.Error("cannot read root", "error", err)
		os.Exit(1)
	}
	logger.Info("current root", "size", recovery.EntriesLoaded, "root", root.String())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           service.New(store, logger).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Shut down on a signal rather than being killed mid-append. An append
	// that is interrupted after write but before fsync is recoverable, but
	// recovering costs an operator a warning they then have to investigate,
	// and a clean exit avoids manufacturing one.
	idle := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		logger.Info("shutting down")
		if err := srv.Close(); err != nil {
			logger.Error("shutdown", "error", err)
		}
		close(idle)
	}()

	fmt.Fprintf(os.Stderr, "sentinel listening on http://%s\n", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
	<-idle
}
