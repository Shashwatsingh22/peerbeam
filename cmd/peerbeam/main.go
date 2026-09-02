// Command peerbeam is the Peerbeam entrypoint: a single self-contained executable per operating
// system and architecture, with the command line as its only interface (Req 12.2, 12.6).
//
// This file stays thin. The command tree is assembled in internal/app, so the only things here are
// signal handling and the single exit path.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/peerbeam/peerbeam/internal/app"
)

// version and commit are set at link time by the release build (-X main.version=...). They default to
// "dev" so a `go build` with no ldflags still reports something honest rather than an empty string.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "peerbeam:", err)
		os.Exit(1)
	}
}

// run holds the body of the program so that every exit path returns an error value instead of calling
// os.Exit from deep inside the call tree.
//
// The context is cancelled on SIGINT and SIGTERM, and it reaches every command through
// cobra's ExecuteContext. That is what makes `peerbeam status --watch` stop on the first Ctrl-C
// rather than needing a second one: the ticker loop selects on the same context the signal cancels.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := app.NewRootCommand(app.NewProductionNode)
	root.Version = version + " (" + commit + ")"

	if err := root.ExecuteContext(ctx); err != nil {
		// A cancelled context is the user pressing Ctrl-C, which is not a failure worth an
		// error message or a non-zero exit.
		if errors.Is(err, context.Canceled) {
			return nil
		}
		// A command that already printed its own complete report exits non-zero without the
		// message being printed a second time in a thinner form.
		if errors.Is(err, app.ErrAlreadyReported) {
			os.Exit(1)
		}
		return err
	}
	return nil
}
