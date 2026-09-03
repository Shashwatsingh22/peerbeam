#!/bin/sh
# Builds and installs the macOS Bluetooth shim.
#
# The Info.plist is embedded into the executable rather than shipped beside it. A bare command-line
# tool has no bundle, and since macOS 11 CoreBluetooth requires an NSBluetoothAlwaysUsageDescription
# to be reachable or TCC denies the request without ever prompting. Linking the plist into a
# __TEXT,__info_plist section is how a single-file executable carries one.
#
# The shim is installed to ~/.peerbeam/bin/peerbeam-bt-shim, which is where bt.ShimPath looks by
# default. Set PEERBEAM_BT_SHIM to override that.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
source_file="$here/peerbeam_bt_macos.swift"
plist="$here/Info.plist"

install_dir="${PEERBEAM_SHIM_DIR:-$HOME/.peerbeam/bin}"
binary="$install_dir/peerbeam-bt-shim"

if [ "$(uname -s)" != "Darwin" ]; then
	echo "this shim is macOS only; on Linux and Windows the equivalent lives in shim/linux and shim/windows" >&2
	exit 1
fi

if ! command -v swiftc >/dev/null 2>&1; then
	echo "swiftc not found. install the Xcode command line tools with: xcode-select --install" >&2
	exit 1
fi

mkdir -p "$install_dir"

echo "building peerbeam-bt-shim"
swiftc \
	-O \
	-target "$(uname -m)-apple-macos13.0" \
	-framework CoreBluetooth \
	-framework Foundation \
	-Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$plist" \
	-o "$binary" \
	"$source_file"

chmod 0755 "$binary"

echo "installed $binary"

# Verify the plist actually made it into the section. A missing plist is not a build error, it is a
# silent TCC denial at runtime, so it is worth checking here rather than debugging it later.
if otool -s __TEXT __info_plist "$binary" >/dev/null 2>&1 &&
	otool -s __TEXT __info_plist "$binary" | grep -q .; then
	echo "embedded Info.plist verified"
else
	echo "WARNING: no __TEXT,__info_plist section found; Bluetooth will be denied at runtime" >&2
	exit 1
fi

cat <<'EOF'

One more step, and it is not optional.

A command-line tool inherits its Bluetooth permission from whatever launched it, so macOS checks
the terminal, not this binary. Grant your terminal Bluetooth access:

  System Settings > Privacy & Security > Bluetooth > enable your terminal
  (Terminal, iTerm, Ghostty, or whichever you use - and your editor if you run peerbeam from it)

Without that, CoreBluetooth reports "unauthorized" and Peerbeam will report BT_Transport as
unavailable. You may need to quit and reopen the terminal after granting it.
EOF
