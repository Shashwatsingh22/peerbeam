module github.com/peerbeam/peerbeam

go 1.23

require (
	github.com/spf13/cobra v1.8.1 // CLI command tree
	golang.org/x/crypto v0.31.0 // X25519 (curve25519) + ChaCha20-Poly1305
	pgregory.net/rapid v1.1.0 // property-based testing (test only)
)

// Windows ACLs for the identity key file (Req 9.1); direct since permissions_windows.go.
require golang.org/x/sys v0.28.0

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)
