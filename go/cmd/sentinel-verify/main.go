// Command sentinel-verify audits a Sentinel log without trusting it.
//
// Builds with CGO_ENABLED=0 and links nothing from sentinel-core, which is
// the point: an auditor should be a single static binary you can hand to
// someone who does not run the log and has no reason to believe its operator.
//
// Subcommands:
//
//	root                       fetch and print the current root
//	audit                      verify every entry's inclusion, plus a sample of consistency proofs
//	monitor -size N -root HEX   prove the log now extends the one you saw before
//	entry -position N          fetch one entry and verify its inclusion proof
//	append -data STRING        submit an entry (not an audit operation; here for demos)
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/LegendaryPenguin/sentinel/audit"
	"github.com/LegendaryPenguin/sentinel/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// Exit codes are meaningful because this is a tool that belongs in a cron
	// job: 0 verified, 1 could not complete, 2 misuse, and 3 specifically for
	// "the log failed verification", so an alert can distinguish a network
	// blip from evidence of tampering.
	switch os.Args[1] {
	case "root":
		os.Exit(cmdRoot(os.Args[2:]))
	case "audit":
		os.Exit(cmdAudit(os.Args[2:]))
	case "monitor":
		os.Exit(cmdMonitor(os.Args[2:]))
	case "entry":
		os.Exit(cmdEntry(os.Args[2:]))
	case "append":
		os.Exit(cmdAppend(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sentinel-verify — audit a Sentinel transparency log

usage: sentinel-verify <subcommand> [flags]

subcommands:
  root                          print the current size and root
  audit                         verify every entry and a sample of consistency proofs
  monitor -size N -root HEX     prove the log extends a root you saved earlier
  entry -position N             fetch one entry and verify its inclusion proof
  append -data STRING           submit an entry (for demos; not an audit operation)

common flags:
  -server URL                   log to audit (default http://127.0.0.1:8080)
  -timeout DURATION             overall deadline (default 2m)

exit codes:
  0  verified
  1  could not complete (network, bad arguments to the server)
  2  misuse
  3  VERIFICATION FAILED — the log's answers do not add up
`)
}

type common struct {
	server  string
	timeout time.Duration
}

func addCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.server, "server", "http://127.0.0.1:8080", "log to audit")
	fs.DurationVar(&c.timeout, "timeout", 2*time.Minute, "overall deadline")
	return c
}

// classify turns an error into an exit code.
//
// A verification failure and a network failure are different events and an
// operator must be able to tell them apart from the exit status alone — the
// first means someone may have rewritten history, the second means the log
// was unreachable.
func classify(err error) int {
	switch {
	case errors.Is(err, verify.ErrRootMismatch),
		errors.Is(err, verify.ErrProofTooShort),
		errors.Is(err, verify.ErrProofTooLong),
		errors.Is(err, verify.ErrExpectedEmptyProof),
		errors.Is(err, verify.ErrIndexOutOfRange),
		errors.Is(err, verify.ErrSizesReversed),
		errors.Is(err, audit.ErrServerMisbehaved):
		return 3
	default:
		return 1
	}
}

func fail(err error) int {
	code := classify(err)
	if code == 3 {
		fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	return code
}

func cmdRoot(args []string) int {
	fs := flag.NewFlagSet("root", flag.ExitOnError)
	c := addCommon(fs)
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	r, err := audit.New(c.server).Root(ctx)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("size %d\nroot %s\n", r.Size, r.Root)
	return 0
}

func cmdAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	c := addCommon(fs)
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	start := time.Now()
	report, err := audit.New(c.server).AuditAll(ctx)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("verified %d entries and %d consistency proofs against root %s (size %d) in %s\n",
		report.EntriesVerified, report.ConsistencyPairs, report.Root, report.Size,
		time.Since(start).Round(time.Millisecond))
	return 0
}

func cmdMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	c := addCommon(fs)
	size := fs.Uint64("size", 0, "size of the log when you last saw it")
	rootHex := fs.String("root", "", "root you saved at that size (64 hex characters)")
	_ = fs.Parse(args)

	if *rootHex == "" {
		fmt.Fprintln(os.Stderr, "monitor: -root is required")
		fmt.Fprintln(os.Stderr, "  for a first run, use size 0 and the empty root:")
		fmt.Fprintf(os.Stderr, "    -size 0 -root %s\n", verify.HashEmpty())
		return 2
	}
	saved, err := verify.ParseHash(*rootHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "monitor: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	current, err := audit.New(c.server).Monitor(ctx, audit.SignedRoot{Size: *size, Root: saved})
	if err != nil {
		return fail(err)
	}
	fmt.Printf("the log at size %d is an append-only extension of size %d\n", current.Size, *size)
	fmt.Printf("size %d\nroot %s\n", current.Size, current.Root)
	return 0
}

func cmdEntry(args []string) int {
	fs := flag.NewFlagSet("entry", flag.ExitOnError)
	c := addCommon(fs)
	position := fs.Uint64("position", 0, "entry position")
	treeSize := fs.Uint64("tree-size", 0, "tree size to prove against (0 means current)")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	client := audit.New(c.server)
	var root verify.Hash
	size := *treeSize
	if size == 0 {
		r, err := client.Root(ctx)
		if err != nil {
			return fail(err)
		}
		size, root = r.Size, r.Root
	} else {
		r, err := client.RootAt(ctx, size)
		if err != nil {
			return fail(err)
		}
		root = r.Root
	}

	entry, err := client.VerifyInclusion(ctx, *position, size, root)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("position  %d\n", entry.Position)
	fmt.Printf("timestamp %s\n", time.Unix(0, int64(entry.TimestampNanos)).UTC().Format(time.RFC3339Nano))
	fmt.Printf("payload   %s\n", base64.StdEncoding.EncodeToString(entry.Payload))
	fmt.Printf("verified against root %s at size %d\n", root, size)
	return 0
}

func cmdAppend(args []string) int {
	fs := flag.NewFlagSet("append", flag.ExitOnError)
	c := addCommon(fs)
	data := fs.String("data", "", "payload to append")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	position, size, err := audit.New(c.server).Append(ctx, []byte(*data))
	if err != nil {
		return fail(err)
	}
	fmt.Printf("appended at position %d; log is now %d entries\n", position, size)
	return 0
}
