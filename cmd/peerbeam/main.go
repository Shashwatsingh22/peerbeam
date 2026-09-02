// Command peerbeam is the Peerbeam entrypoint: a single self-contained
// executable per operating system and architecture, with the command line as
// its only interface.
//
// This file stays deliberately thin. The cobra root command and its subcommand
// tree are assembled in internal/app and attached here once that wiring exists.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "peerbeam:", err)
		os.Exit(1)
	}
}

// run holds the body of the program so that every exit path returns an error
// value instead of calling os.Exit from deep inside the call tree.
func run() error {
	fmt.Println("peerbeam: no commands are wired up yet")
	return nil
}
