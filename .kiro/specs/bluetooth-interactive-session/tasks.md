# Implementation Plan: Bluetooth and the Interactive Session

## Overview

This plan is ordered by dependency, not by layer, because each stage is independently observable and the riskiest work is first. The BT_Shim comes before everything: if CoreBluetooth cannot be made to advertise and open channels from a command-line tool, the rest of the plan changes shape, so that question is settled before any Go code is written. Presence wiring comes next, because it is what makes a Peer appear at all. Pairing comes third, because two fresh machines cannot reach an established Session without it. The Interactive_Session comes last, because it is a consumer of all three.

Tasks marked `*` are test sub-tasks and may be deferred for a faster path to something runnable, but the design treats property tests as central, so implementing them is strongly recommended.

The Go side of Bluetooth needs no changes: `BluetoothBridge`, `BtTransport`, `ShimBluetoothBridge`, and the in-process fabric are already implemented and tested. Tasks 1 and 2 add native code and a build; they do not touch `internal/platform/bt`.

Language and toolchain: Go 1.23 for the node, Swift for the macOS shim, built with `swiftc` from the Xcode command line tools. No new Go dependencies.

## Tasks

- [x] 1. Implement the macOS BT_Shim
  - [x] 1.1 Write the Shim_Frame protocol layer in Swift
    - Create `shim/macos/peerbeam_bt_macos.swift` with the `ShimKind` enum matching the twelve kinds in `internal/platform/bt/shimbridge.go`, the 9-byte header constant, and the 64 KiB payload maximum
    - Implement a frame writer holding a mutex across each write, so two callbacks cannot interleave halves of a frame
    - Implement a reader thread doing blocking reads of exactly the header then exactly the payload, dispatching each frame onto the main queue
    - Exit on standard input closing, which is the node's documented shutdown signal
    - Send diagnostics to standard error only; standard output carries frames and nothing else
    - _Requirements: 1.4, 1.5, 1.6_
  - [x] 1.2 Implement the peripheral role
    - Advertise the service UUID `50454552-4245-414D-0000-000000000001` with a short local name; do not attempt to advertise the record, which does not fit
    - Add a GATT service with a read-only record characteristic and a read-only PSM characteristic
    - Publish an L2CAP channel with `withEncryption: false` and hold the assigned PSM
    - Serve the record honouring `request.offset`, since a 2048-byte value spans several ATT reads
    - Accept inbound L2CAP channels, allocate an inbound stream identifier with the high bit set, and emit `accepted`
    - _Requirements: 1.3, 1.8, 3.4_
  - [x] 1.3 Implement the central role
    - Scan for the service UUID; on discovery, connect and read the peer's record
    - Emit `scanResult` with the device identifier, a null byte, then the record, matching `splitDeviceRecord`
    - On `connect`, read the peer's PSM characteristic then open an L2CAP channel, emitting `connected` on success and `error` on failure
    - Drop the GATT link after reading a record when no connect is outstanding, keeping the identifier for a later dial
    - _Requirements: 1.3, 4.1, 4.2_
  - [x] 1.4 Pump L2CAP channels as byte streams
    - Bridge each channel's input stream to `data` frames and `data` frames to its output stream
    - Buffer writes and resume from `hasSpaceAvailable`, because an `OutputStream` accepts bytes only while it reports space; dropping the remainder would truncate a Wire_Frame
    - Emit `close` on end of stream and `error` on stream failure, and remove the stream from the table
    - _Requirements: 1.7_
  - [x] 1.5 Report availability truthfully
    - Emit `available` once per change, only when both the central and peripheral managers are powered on, so the value does not flap while the managers come up
    - Log the specific radio state so a powered-off radio, a denied authorization, and an unsupported host are distinguishable
    - _Requirements: 1.2, 2.1, 2.5_

- [x] 2. Build and install the shim
  - [x] 2.1 Write `shim/macos/Info.plist` and `shim/macos/build.sh`
    - Declare `NSBluetoothAlwaysUsageDescription`; without it TCC denies Bluetooth outright rather than prompting
    - Compile with `swiftc`, linking the plist into `__TEXT,__info_plist` with `-sectcreate`, since a command-line tool has no bundle
    - Verify with `otool` that the section is present in the output and fail the build if it is not
    - Install to `~/.peerbeam/bin/peerbeam-bt-shim`, which is where `bt.ShimPath` looks, honouring an override
    - Print the terminal-grant instruction, because the authorization applies to the launching process
    - _Requirements: 1.1, 2.2, 2.3, 2.4_
  - [x] 2.2 Add a `make shim` target and rewrite `shim/macos/README.md`
    - Dispatch on `uname -s`; fail with a pointer to the relevant directory on Linux and Windows
    - Document the UUID layout, why CoreBluetooth replaced the IOBluetooth RFCOMM the README originally specified, and the terminal grant
    - _Requirements: 1.1, 2.4, 11.1_
  - [x] 2.3 Verify the shim against the real radio on one machine
    - Drive it over the real protocol and confirm it reports available, publishes a PSM, and advertises
    - Confirm `peerbeam status` no longer reports BT_Transport unavailable
    - _Requirements: 1.1, 1.3, 2.1_

- [x] 3. Make `PeerRegistry` safe for concurrent use
  - Add a mutex inside the registry guarding `Observe`, `AddManual`, `Expire`, `Visible`, `MediaFor`, and `Len`
  - Take the lock after the pure validation in `Observe` and `AddManual`, so one malformed record does not serialise every source's parsing
  - Correct the type comment, which documented a single-goroutine assumption that two Presence_Sources break
  - _Requirements: 4.6_

- [x] 4. Wire Presence_Sources into the node
  - [x] 4.1 Define `PresenceSource` and the two adapters
    - Create `internal/app/presence.go` with the `PresenceSource` interface (`Medium()`, `Run(ctx)`)
    - Implement `lanPresence` over `*lan.Beacon`, whose `Start` already blocks until the context is done
    - Implement `btPresence` over `*bt.BtTransport`, running an advertise ticker and `ScanInto`
    - Republish the Bluetooth advertisement on a ticker rather than once, to satisfy the republish interval and to recover a restarted shim
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [x] 4.2 Add `Ports.Presence` and run the sources from `Start`
    - Add the field, documented as optional so the in-process tests can keep placing peers directly
    - Start one goroutine per source under the root context, joined by the existing wait group
    - Report a source that fails after starting, naming the medium, and leave the others running
    - _Requirements: 3.1, 3.6_
  - [x] 4.3 Build the sources in `wiring.go`
    - Construct them after the node exists, since each needs the registry and the announcement
    - Wire the malformed and observed callbacks to the existing event log path
    - Publish the port actually bound rather than the requested one
    - _Requirements: 3.5, 4.3, 4.4_
  - [x] 4.4* Property tests for presence composition
    - Property 46: two sources, expiry, and reads compose without losing observations; one entry per fingerprint; every medium listed. Run under `-race`
    - Property 47: a malformed record produces identical reasons and an identical unchanged list on the Bluetooth and LAN paths
    - _Requirements: 4.3, 4.5, 4.6_

- [x] 5. Start the node behind the commands that need one
  - [x] 5.1 Add a starting opener and classify the commands
    - Add an opener that starts the node and returns a stop function alongside the existing constructing one
    - Move `peers`, `peers add`, `pair`, `connect`, `send`, `clip *`, and `status --watch` onto it; leave `trust list`, `trust remove`, `log tail`, and plain `status` on the constructing one
    - _Requirements: 5.1, 5.2, 5.4_
  - [x] 5.2 Wait for discovery before rendering a peer list
    - Allow a bounded interval for the first observation and say that discovery is in progress, rather than printing an empty table immediately
    - _Requirements: 5.5, 6.3_
  - [x] 5.3 Route interruption through the single stop path
    - Cancel the root context on signal, which closes the shim's standard input and stops every loop through `PeerNode.Stop`
    - Confirm no shim process survives the node exiting
    - _Requirements: 5.3_

- [ ] 6. Implement the Pairing_Exchange
  - [ ] 6.1 Add the message types and payload codecs
    - Add `PairingOffer` and `PairingDecision` codes to `internal/core/codec/messagetype.go`
    - Encode and decode the offer as version, length-prefixed public key, length-prefixed display name; the decision as a single byte where anything other than 0 or 1 is malformed
    - _Requirements: 9.1_
  - [ ] 6.2 Implement the exchange over a connection
    - Create `internal/app/pairing.go` driving the symmetric sequence: send an offer, receive one, derive the code, wait for the local decision, exchange decisions, complete on mutual confirmation
    - Derive the code locally from both public keys; never transmit it
    - Apply the 120-second code validity as the deadline for the whole exchange
    - Feed a key that contradicts a stored one into the existing key-mismatch path rather than a new report
    - Prompt the local user on an inbound offer instead of accepting automatically
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.9_
  - [ ] 6.3 Refuse everything else before trust exists
    - Process only pairing and key exchange messages on a connection with no trust, leaving all Session and trust state untouched for anything else
    - _Requirements: 9.8_
  - [ ] 6.4* Property tests for pairing
    - Property 48: both sides derive an equal code, and no encoded frame contains its digits
    - Property 49: over all four decision combinations, trust is recorded in exactly one
    - Property 50: a mismatched key reports a key mismatch, never an untrusted peer, and records no trust
    - Property 51: any other message type before trust leaves all state untouched
    - _Requirements: 9.2, 9.4, 9.5, 9.7, 9.8_

- [ ] 7. Build the Interactive_Session
  - [ ] 7.1 Implement the state machine
    - Create `internal/app/interactive.go` with the Discovering, PeerPicker, Connecting, Pairing, and ChatView states
    - Take input through an interface and write to an `io.Writer`, so the machine is testable with no terminal
    - Return to the PeerPicker on every terminal edge; reach exit only on an explicit quit
    - _Requirements: 6.1, 7.3, 8.7, 8.8_
  - [ ] 7.2 Implement the Peer_Picker
    - Display a selection index, display name, abbreviated fingerprint, and media per Peer, marking which are already trusted
    - Snapshot the list on display and resolve a selection to a fingerprint, so an expiry between display and selection cannot connect to the wrong Peer
    - Say discovery is in progress when the list is empty; offer explicit rescan and quit
    - Reject an invalid selection and redisplay without exiting
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 6.6, 6.7_
  - [ ] 7.3 Implement connection with progress
    - Name each Transport as it is attempted, in ranked order
    - On success, state that the connection is established and name the Peer and active Transport before accepting input
    - On total failure, report every Transport tried and why, then return to the picker
    - Enter the Pairing state first when the Peer is not trusted
    - _Requirements: 6.4, 7.1, 7.2, 7.3, 7.4_
  - [ ] 7.4 Implement the Chat_View
    - Send each submitted line as a text Message; send nothing for an empty line
    - Supply a `TextDisplay` so inbound Messages arrive through the existing router path
    - Distinguish sent from received lines and attribute received ones to the sender's display name
    - Refuse an oversized line, say why, and stay open; report a send failure against that Message and stay open
    - Repaint so an arriving Message does not corrupt a partially typed line
    - Surface transport changes and the disconnected state as inline notices, saying that Messages are being queued
    - _Requirements: 7.5, 7.6, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.9_
  - [ ] 7.5 Make it the default command and report through the single mapping
    - Run the Interactive_Session when the binary is invoked with no subcommand
    - Render every failure through `report.Describe`; show the startup report once at entry
    - Use the all-or-nothing status rule wherever status is displayed
    - _Requirements: 10.1, 10.3, 10.4_
  - [ ] 7.6* Property tests for the interactive layer
    - Property 52: a selection resolves to the Peer displayed at that index, or reports it is gone; never a different Peer
    - Property 53: an arriving Message leaves the typed buffer unchanged
    - Property 54: every terminal edge reaches the PeerPicker; only quit reaches exit
    - Property 55: no rendered line contains key material or any payload beyond the text the user sent or received
    - _Requirements: 6.7, 8.3, 10.2_

- [ ] 8. Shim protocol property tests
  - [ ] 8.1* Test the frame layer against a pipe
    - Property 42: frames cut at arbitrary offsets, including mid-header, read back identically and in order
    - Property 43: node-allocated and shim-allocated identifier spaces never collide
    - Property 44: a shim exit or oversized declaration fails every open stream and blocks none
    - Property 45: an oversized declared length is refused before the payload is read
    - _Requirements: 1.7_

- [ ] 9. Cross-target and packaging checks
  - Confirm every release target of the parent spec still builds and vets with no shim present
  - Confirm a host with no shim reaches ready state, reports BT_Transport unavailable, and runs LAN-only
  - Confirm `make release` still produces one executable per target under the size ceiling
  - _Requirements: 11.1, 11.2_

- [ ] 10. Two-machine verification and documentation
  - [ ] 10.1 Verify across two machines
    - Build and install the shim on both; grant Bluetooth to the terminal on both
    - With both off any shared network, confirm each appears in the other's Peer list, that pairing completes with matching codes on both, that the Session establishes over BT_Transport, and that Messages travel both ways
    - Confirm a rejected code records no trust, and that an expired code is reported
    - Measure goodput and round-trip time on the Bluetooth link and record them against the ranking figure
    - _Requirements: 1.3, 4.1, 7.2, 8.1, 8.2, 9.3, 9.4, 9.5, 9.6_
  - [ ] 10.2 Update the README
    - Document the shim build, the terminal Bluetooth grant, and the interactive flow
    - Correct the status table: discovery and the interactive session now work in the assembled binary
    - Keep the remaining gaps honest: the Transfer sender loop, the Windows and Linux shims, and the two-file deliverable
    - Restate the non-goals so the scope is not mistaken: no relay or NAT traversal, and AirDrop stays a manual share-sheet handoff rather than a Transport
    - _Requirements: 11.1, 11.3, 11.4, 11.5, 11.6_
