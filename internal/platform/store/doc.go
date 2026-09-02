// Package store is the on-disk state adapter for the identity key and the
// trust store under ~/.peerbeam. It implements the KeyStore and TrustStore
// interfaces: identity.key written owner-readable only, via POSIX mode 0600 on
// macOS and Linux and via a current-user-only ACL on Windows, and
// trusted.json carrying an HMAC-SHA256 tag over its canonical entry bytes.
//
// A failed key generation, a failed permission step, or a failed tag check is
// reported with the failing step named so the node can refuse session requests
// until it succeeds.
package store
