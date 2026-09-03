# macOS native shim

`peerbeam_bt_macos.swift` is the Bluetooth helper for `internal/platform/bt`. Build and
install it with:

```sh
make shim          # or: ./shim/macos/build.sh
```

That writes `~/.peerbeam/bin/peerbeam-bt-shim`, which is where `bt.ShimPath` looks by
default. `PEERBEAM_BT_SHIM` overrides the location.

## Grant your terminal Bluetooth access

**This is required, and it is not about this binary.** A command-line tool inherits its
Bluetooth permission from the process that launched it, so macOS checks your terminal.

    System Settings > Privacy & Security > Bluetooth > enable your terminal

Without it CoreBluetooth reports `unauthorized`, and the shim logs
`bluetooth is not available: central=unauthorized`. Quit and reopen the terminal after
granting it.

## Why CoreBluetooth and not IOBluetooth RFCOMM

This file originally specified IOBluetooth Classic RFCOMM. That needs an SDP service
record plus an OS-level pairing between the two machines before a channel can open, and
Apple has been retiring the Classic serial profiles. CoreBluetooth needs neither: two
machines find each other by service UUID and open a channel with no pairing prompt, and
it is the supported API on current macOS.

L2CAP connection-oriented channels rather than GATT characteristic writes, because
`CBL2CAPChannel` exposes a real bidirectional byte stream, which is exactly what
`BluetoothBridge` is declared in terms of. Carrying a stream over GATT would have meant
reimplementing framing and flow control on top of a request/response protocol.

## How it works

Each machine runs both Bluetooth roles at once:

| Role | Job |
| --- | --- |
| peripheral | advertise the service UUID, serve the announcement record and the L2CAP PSM over GATT, accept inbound channels |
| central | scan for the service UUID, read a discovered peer's record, open outbound channels |

| UUID | Purpose |
| --- | --- |
| `50454552-4245-414D-0000-000000000001` | service |
| `...-000000000002` | announcement record, read |
| `...-000000000003` | L2CAP PSM, read, 2 bytes big-endian |

An announcement record is up to 2048 bytes and a BLE advertisement carries about 31, so
the advertisement is only the service UUID and a short local name; the record is read
over GATT once a peer is discovered. That extra round trip is what the 15-second
discovery budget in Req 1.4 pays for.

The PSM cannot be a constant: it is assigned when the peripheral publishes its channel,
so a connecting central reads it from the peer before opening the channel.

Link-layer encryption is off (`withEncryption: false`). The session above already seals
every payload with ChaCha20-Poly1305 keyed by the handshake, so requiring it here would
force an OS pairing prompt on both machines and add nothing.

## Not done here yet

The `NSSharingServicePicker` share sheet entry point is not in this file.
`internal/platform/share` reaches the share sheet through `osascript` instead, so
`peerbeam airdrop` works without this shim.
