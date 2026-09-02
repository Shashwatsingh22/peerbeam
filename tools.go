//go:build tools

// This file exists only to pin the module's direct dependencies in go.mod at
// the versions the design fixes, before the packages that actually use them are
// written. The `tools` build tag excludes it from every real build, but
// `go mod tidy` reads imports across all build configurations, so these
// requirements survive a tidy instead of being demoted to indirect or dropped.
//
// Delete this file once cobra, x/crypto, and rapid are all imported by real
// code: cobra in internal/app (task 21.2), x/crypto in internal/core/crypto,
// rapid in the first property test (task 2.4).
package tools

import (
	_ "github.com/spf13/cobra"
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/crypto/curve25519"
	_ "pgregory.net/rapid"
)
