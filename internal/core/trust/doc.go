// Package trust holds the trust model: public key fingerprints, the trusted
// peer entry, the KeyStore and TrustStore interfaces, the symmetric six-digit
// pairing verification code, and the pairing outcome decision.
//
// Pure logic only. Key and trust files are persisted by the adapters in
// internal/platform/store; this package must not import net, os, or any
// socket API.
package trust
