//go:build !darwin

package share

import "runtime"

// newPlatformSharePort returns the rejecting port on every operating system other than macOS
// (Req 12.5).
//
// This is a build-tagged stub rather than a runtime check so the macOS implementation, and the
// cgo shim it will call, are not compiled into a Linux or Windows binary at all. A runtime check
// would drag Objective-C into every build to serve a branch that can never be taken.
func newPlatformSharePort() SharePort {
	return &unsupportedSharePort{operatingSystem: runtime.GOOS}
}
