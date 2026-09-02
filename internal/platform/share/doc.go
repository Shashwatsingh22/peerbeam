// Package share is the macOS share sheet adapter behind the airdrop command.
// It calls the macOS shim's share sheet entry point over cgo, which drives
// NSSharingServicePicker and hands the chosen path to the system, leaving the
// actual AirDrop negotiation to macOS.
//
// On every other operating system the operation rejects immediately as
// macOS-only and touches nothing.
package share
