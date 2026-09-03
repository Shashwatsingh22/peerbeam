# Design Document

## Overview

Three additions and one correction, in dependency order:

1. **A native BT_Shim for macOS**, so `BluetoothBridge.Available()` is true on a real host and BT_Transport becomes a candidate.
2. **Presence_Sources wired into `PeerNode.Start`**, so the visible Peer list is populated on both media.
3. **A Pairing_Exchange**, so two machines meeting for the first time can establish trust.
4. **An Interactive_Session command**, which holds a live Peer_Node, presents the Peer list, and runs a Chat_View.

The correction is that `PeerRegistry` had to become safe for concurrent use before two Presence_Sources could feed it. That has already landed.

The guiding constraint from the parent design is unchanged and is what keeps this feature small: **all decision logic is pure, all I/O sits behind narrow interfaces.** Nothing here adds a decision to `internal/core` that could not be tested without a radio, and nothing here reimplements ranking, framing, sequencing, or crypto per medium.

### What this feature does not have to build

The parent spec left more of this finished than is obvious, and the design leans on it:

| Already implemented and tested | Where |
| --- | --- |
| `BluetoothBridge` interface, `BtTransport`, write splitting at the link MTU | `internal/platform/bt/{bridge,transport}.go` |
| The Shim_Frame protocol client, stream multiplexing, teardown on shim failure | `internal/platform/bt/shimbridge.go` |
| An in-process Bluetooth fabric for tests, with partitioning | `internal/platform/bt/bridge.go` |
| Multicast presence publication and reception | `internal/platform/lan/beacon.go` |
| Fingerprints, the 6-digit code, both confirmation sides, the trust store | `internal/core/trust`, `internal/platform/store` |
| Node lifecycle with a single join point, per-Session goroutines, the router | `internal/app/{peernode,establish,router}.go` |
| Ranking, the connection ladder, switch policy, rebinding | `internal/core/transport` |

So the Go side of Bluetooth needs **no changes at all**. The shim is written against a protocol that already has a tested client.

---

## Architecture

### Where the new pieces sit

```
  cmd/peerbeam ──▶ internal/app
                     │
                     ├── interactive.go      Peer_Picker + Chat_View state machine   (new)
                     ├── presence.go         PresenceSource, LAN and BT adapters     (new)
                     ├── pairing.go          Pairing_Exchange over a connection      (new)
                     ├── peernode.go         Start runs the Presence_Sources         (edit)
                     └── wiring.go           builds the Presence_Sources             (edit)
                                │
        ┌───────────────────────┴────────────────────┐
        ▼                                            ▼
  internal/platform/lan                      internal/platform/bt
        Beacon (exists)                            BtTransport (exists)
                                                   ShimBluetoothBridge (exists)
                                                          │ stdin/stdout, Shim_Frames
                                                          ▼
                                                   shim/macos  peerbeam-bt-shim   (new)
                                                          │ CoreBluetooth
                                                          ▼
                                                     Bluetooth radio
```

`internal/core` gains nothing except new message type codes. That is the intended shape: this feature is wiring and I/O, and the decisions it needs already exist.

### Why a helper process rather than cgo

The parent design offered both: Option A links per-OS native code over cgo, Option B runs it as a helper process speaking a framed protocol. This feature takes **Option B**, and it is worth stating why, because Option A is what release builds eventually want.

- The shim can be rebuilt, restarted, logged, and debugged without rebuilding or restarting the Peer_Node. For first native code against an unfamiliar framework, that iteration speed dominates.
- A native crash kills the shim, not the node. `ShimBluetoothBridge.shimFailed` already fails every open stream so Sessions rebind, which is a far better failure mode than taking the process down.
- `make release` stays `CGO_ENABLED=0` and every target keeps cross-compiling from one machine. Option A needs a cross toolchain per target.
- Nothing above `BluetoothBridge` can tell the difference, so moving to Option A later changes one file.

The cost is that the deliverable is two files rather than one, which is in tension with the parent spec's Requirement 12.2. That is accepted for now and recorded as a risk below.

### Why CoreBluetooth rather than IOBluetooth RFCOMM

`shim/macos/README.md` originally specified IOBluetooth Classic RFCOMM with CoreBluetooth as a fallback. This design inverts that and drops RFCOMM.

RFCOMM requires an SDP service record and an operating-system pairing between the two machines before a channel opens. The OS pairing is the fatal part: it is a second, redundant trust ceremony that the user must complete in System Settings, on top of the verification code this application already derives, and it buys nothing, because the Session encrypts every payload regardless. Apple has also been retiring the Classic serial profiles.

CoreBluetooth needs neither. Two machines find each other by service UUID and open a channel with no prompt. It is the supported API on current macOS.

Within CoreBluetooth, **L2CAP connection-oriented channels** rather than GATT characteristic writes, because `CBL2CAPChannel` exposes a real bidirectional byte stream, which is exactly what `BluetoothBridge` is declared in terms of. Carrying a stream over GATT would mean reimplementing framing and flow control on top of a request/response protocol, directly against the parent design's rule that nothing be reimplemented per medium.

The consequence to accept: BLE throughput is far below the parent spec's 40 KiB/s BT_Transport figure in the worst case. That figure is used for **ranking only** — it decides that LAN sorts above Bluetooth, which stays true — so a slower real link changes no decision. Measured goodput is reported from actual samples.

---

## Components and Interfaces

### 1. BT_Shim (Requirements 1, 2)

A single Swift executable. It speaks the existing Shim_Frame protocol and nothing else on standard output.

```
offset  size  field
  0      1    kind        u8
  1      4    streamId    u32 big-endian, 0 for control frames
  5      4    length      u32 big-endian, at most 65536
  9      N    payload
```

Kinds, unchanged from `shimbridge.go`:

| Direction | Kind | Payload |
| --- | --- | --- |
| node → shim | `startAdvertising` 1 | Announcement_Record |
| node → shim | `stopAdvertising` 2 | — |
| node → shim | `scan` 3 | — |
| node → shim | `connect` 6 | device identifier, UTF-8 |
| node → shim | `data` 9 | stream bytes |
| node → shim | `close` 10 | — |
| shim → node | `scanResult` 4 | device id, `0x00`, Announcement_Record |
| shim → node | `scanDone` 5 | — |
| shim → node | `connected` 7 | — |
| shim → node | `accepted` 8 | — |
| shim → node | `data` 9 | stream bytes |
| shim → node | `close` 10 | — |
| shim → node | `error` 11 | reason, UTF-8 |
| shim → node | `available` 12 | one byte, non-zero for available |

**Stream identifier allocation.** The node numbers outbound streams from 1 upward; the shim numbers inbound streams with the high bit set. Two allocators over one identifier space would otherwise collide, and a collision would silently cross two conversations.

**Both roles at once.** Each machine must be findable and able to find, so the shim runs a peripheral and a central simultaneously:

| Role | Responsibilities |
| --- | --- |
| peripheral | advertise the service UUID; serve the Announcement_Record and the PSM over GATT; accept inbound L2CAP_Channels |
| central | scan for the service UUID; read a discovered peer's Announcement_Record; open outbound L2CAP_Channels |

**GATT layout.** Three fixed UUIDs:

| UUID | Purpose |
| --- | --- |
| `50454552-4245-414D-0000-000000000001` | service |
| `…-000000000002` | Announcement_Record, read |
| `…-000000000003` | PSM, read, 2 bytes big-endian |

**Why the record is served over GATT and not advertised.** An Announcement_Record is up to 2048 bytes (`discovery.MaxAnnouncementBytes`); a BLE advertisement carries roughly 31, and macOS ignores service data and manufacturer data in `startAdvertising` anyway. So the advertisement is only the service UUID plus a short local name, and a central that sees it connects and reads the record. The parent spec's 15-second Bluetooth discovery budget (Requirement 1.4) is what pays for that round trip. The peripheral must honour the read offset, because a 2048-byte value does not fit one ATT response and CoreBluetooth issues a series of reads.

**Why the PSM is read rather than fixed.** The PSM is assigned by the OS when the peripheral publishes its channel, so it differs per machine and per run. A connecting central reads it from the peer immediately before opening the channel.

**Link-layer encryption is off.** `publishL2CAPChannel(withEncryption: false)`. Requiring it forces an OS pairing prompt on both machines and adds nothing: the Session already seals every payload with ChaCha20-Poly1305 keyed by the handshake, and the AEAD tag covers the frame header.

**Threading.** CoreBluetooth callbacks on the main queue, L2CAP streams scheduled on the main run loop, and a dedicated thread doing blocking reads of standard input that dispatches each parsed frame onto the main queue. Single-threaded by construction, so the stream table needs no locking. Writes to standard output take a mutex because a partial frame interleaved with another desynchronises the node's reader permanently.

**Write buffering.** A Foundation `OutputStream` accepts bytes only while it reports space available. A payload larger than the current window must be held and resumed from the `hasSpaceAvailable` callback; dropping the remainder would silently truncate a Wire_Frame, which the codec above would then report as a framing mismatch with no clue as to the cause.

#### Authorization, which is the part that fails silently

Two macOS behaviours, both of which produce a denial with no prompt and no error if missed:

1. **The executable needs an `Info.plist` with `NSBluetoothAlwaysUsageDescription`.** A bare command-line tool has no bundle, so the plist is linked into a `__TEXT,__info_plist` section. Without it TCC cannot present a prompt and denies the request outright. The build script verifies the section is present in the produced binary and fails if it is not, because the alternative is discovering it at runtime as an unexplained `unauthorized` state.
2. **The grant applies to the process that launched the node, not to the node or the shim.** A command-line tool inherits Bluetooth authorization from its parent, so the user must grant Bluetooth access to their *terminal*. This is documented in the build output and the shim README, since no amount of correctness in this code can substitute for it.

The shim distinguishes powered-off, unauthorized, unsupported, and resetting radio states and reports the specific one, so Requirement 2.5 can tell them apart.

### 2. Presence_Source (Requirements 3, 4)

A narrow interface in `internal/app`, so `Start` drives every medium the same way:

```go
// PresenceSource publishes this node's presence on one medium and feeds what it hears into
// the visible Peer list. It is what makes `peerbeam peers` show anything.
type PresenceSource interface {
    // Medium names the source in startup and failure reports.
    Medium() discovery.Medium
    // Run publishes and receives until ctx is done, then returns.
    Run(ctx context.Context) error
}
```

Two adapters:

- **`lanPresence`** wraps `*lan.Beacon`. `Run` is `beacon.Start(ctx)`, which already blocks until the context is done and owns its publish, receive, and expiry loops.
- **`btPresence`** wraps `*bt.BtTransport`. `Run` starts two loops: one calling `StartAdvertising` with the current Announcement_Record on a ticker, one calling `ScanInto` to feed the registry. Both already exist on `BtTransport`.

Advertising is **republished on a ticker** rather than set once, for two reasons: Requirement 3.2 needs a republish interval on the Bluetooth medium to match the parent spec's Requirement 1.9, and a shim that died and was restarted has forgotten what it was advertising. Re-sending is idempotent and cheap.

`Ports` gains one field:

```go
// Presence publishes and discovers on each medium. Empty means no discovery, which is
// what the in-process tests want when they place peers in the registry directly.
Presence []PresenceSource
```

`wiring.go` builds them after the node exists, because a Presence_Source needs the node's registry and announcement.

**Registry concurrency.** Two Presence_Sources plus the expiry ticker plus command-layer reads are four goroutines over one map. The lock lives inside `PeerRegistry` rather than in each caller, because that is the shared mutable state and a lock per caller would mean four mutexes over one map with `bt.ScanInto` and `lan.Beacon` each holding one. `Observe` and `AddManual` take it after their pure validation, so one peer's malformed record does not serialise every other source's parsing. The mutex is a leaf — nothing under it calls out except `Clock.Now` — so there is no ordering to respect. **Already landed.**

### 3. Node lifecycle in the CLI (Requirement 5)

Today `nodeOpener` constructs a node and returns it; nothing starts it. The change is a second opener that starts the node and returns a stop function, and a classification of commands.

| Class | Commands | Node |
| --- | --- | --- |
| local only | `trust list`, `trust remove`, `status` without `--watch`, `log tail` | constructed, not started |
| needs a live node | `peers`, `peers add`, `pair`, `connect`, `send`, `clip *`, `status --watch`, interactive | started, then stopped |

Requirement 5.5 matters for `peers`: a started node still has an empty list for the first few seconds, so the command waits a bounded interval and says it is discovering. Rendering an empty table immediately is what makes the current build look broken.

Stop goes through `PeerNode.Stop`, which is already the single join point. Signal handling in `cmd/peerbeam/main.go` cancels the root context, which cancels the shim's `exec.CommandContext` and closes its standard input, which is the documented shutdown signal for the shim. That satisfies Requirement 5.3 without a second teardown path.

### 4. Pairing_Exchange (Requirement 9)

This is the only new protocol in the feature. Everything except the wire step exists: `PairingService.BeginPairing(peerPublicKey, displayName)` takes the key as a parameter, and nothing ever supplies one from a remote machine. The end-to-end tests hand it over in process, which is exactly the gap.

Two new message types, carried by the existing codec:

| Message | Payload | When |
| --- | --- | --- |
| `PairingOffer` | protocol version, long-term public key, display name | first frame on a first-contact connection |
| `PairingDecision` | one byte: confirmed or rejected | after the local user decides |

Sequence, symmetric on both sides:

1. Dialer opens a connection and sends `PairingOffer`. Listener replies with its own `PairingOffer`.
2. Each side calls `BeginPairing` with the received key and derives the 6-digit code. The code is **never transmitted** (Requirement 9.2) — both sides derive it from the two public keys, sorted, which is what stops an attacker who controls the medium from making them agree on a code of their choosing.
3. Each side shows the code and waits for its own user. `ConfirmLocal` records this side's decision; the outcome stays `PairingPending` until the peer's decision arrives.
4. Each side sends `PairingDecision`. On receiving a confirmation, `ConfirmPeer` completes the pairing and the Peer becomes a Trusted_Peer.
5. Only then does the key exchange and Session handshake proceed.

Rules that fall out of the requirements and the existing code:

- **Nothing but pairing and key exchange is processed before trust exists** (Requirement 9.8). The router already refuses to act on application messages before a Session is up; this extends the same rule to the pairing phase.
- **A key that disagrees with one already held for that fingerprint is a key mismatch, not an untrusted peer** (Requirement 9.7). The parent spec already tests that these are reported distinctly (`TestEndToEndKeyMismatchIsReportedApartFromUntrusted`), so the exchange must feed the existing path rather than inventing a report.
- **An inbound offer prompts the local user** (Requirement 9.9). Auto-accepting an inbound pairing would make the code ceremony decorative.
- **The 120-second code validity is the timeout for the whole exchange** (Requirement 9.6). It already exists in `trust`; this wires a deadline to it.

### 5. Interactive_Session (Requirements 6, 7, 8, 10)

A state machine in `internal/app/interactive.go`, run by a new default command.

```
        ┌──────────────┐  no peers yet
        │  Discovering │──────────────┐
        └──────┬───────┘              │
               │ peer appears         │
               ▼                      │
        ┌──────────────┐              │
   ┌───▶│  PeerPicker  │◀─────────────┘
   │    └──────┬───────┘
   │           │ selection
   │           ▼
   │    ┌──────────────┐  not trusted   ┌──────────┐
   │    │  Connecting  │───────────────▶│  Pairing │
   │    └──────┬───────┘                └────┬─────┘
   │           │ established                 │ confirmed
   │           ▼                             │
   │    ┌──────────────┐◀───────────────────┘
   │    │   ChatView   │
   │    └──────┬───────┘
   └───────────┘ leave, peer closed, or connect failed
```

Every terminal edge returns to the Peer_Picker rather than exiting (Requirements 6.5, 7.3, 8.7, 8.8), because a user who mistyped a selection or picked a machine that went out of range has not asked to quit.

**Selection stability.** Requirement 6.7 forbids indices that shift under the user. The picker snapshots the list when it displays, and a selection index resolves against that snapshot to a *fingerprint*. A Peer that expired between display and selection produces "that peer is no longer visible" rather than connecting to whoever now occupies row 2.

**Concurrent display and input.** The Chat_View has a goroutine printing inbound Messages and a main loop reading standard input. Requirement 8.3 says an arriving Message must not corrupt a partially typed line. A plain `fmt.Println` from the printer goroutine writes over whatever the user has typed so far. The design keeps this simple rather than taking a terminal dependency: the printer emits a carriage return and clears the current line, prints the Message, then reprints the prompt and the user's buffer. That needs the input to be read a rune at a time so the buffer is known, which the design accepts as the cost of the requirement. A full-screen terminal library is explicitly rejected — it would pull in a large dependency and a redraw model for a two-pane text view.

**Where received Messages come from.** `Ports.Display` is the existing `TextDisplay` seam and is documented as "nil writes to standard output". The Chat_View supplies its own implementation, so inbound text arrives through the same path the router already uses. Nothing in the router changes.

**Status and reporting.** Failures render through `report.Describe` (Requirement 10.1), so an interactive failure reads the same as a one-shot command's. The startup report shows once at entry (Requirement 10.3). Transport changes and disconnections are surfaced as inline notices (Requirements 7.5, 7.6) from the existing event stream rather than by polling.

---

## Data Models

### New message type codes

Two codes added to `internal/core/codec/messagetype.go`. The parent design's rule that an unrecognised type is skipped and the stream continues (Property 7) means an older peer meeting a newer one does not desynchronise — it ignores the pairing offer and the connection fails as untrusted, which is the correct outcome.

### `PairingOffer` payload

| Field | Size | Notes |
| --- | --- | --- |
| protocol version | 1 | rejected before anything else if unsupported |
| public key length | 1 | Ed25519 is 32, but length-prefixed so the field is self-describing |
| public key | N | long-term identity |
| display name length | 2 big-endian | |
| display name | N | UTF-8, at most 64 characters per the parent spec |

### `PairingDecision` payload

| Field | Size | Notes |
| --- | --- | --- |
| decision | 1 | 1 confirmed, 0 rejected; any other value is malformed |

### On-disk models

Unchanged. `identity.key` and `trusted.json` keep their formats, permissions, and integrity tag. The Pairing_Exchange writes through `FileTrustStore.Put`, which already does the atomic temp-and-rename write.

---

## Correctness Properties

Numbered from 42 to continue the parent design's 1–41. Each is a `rapid.Check` property test at a minimum of 100 generated cases unless noted otherwise.

### Property 42: Shim frame round trip under arbitrary segmentation

Any sequence of Shim_Frames, written to a pipe and cut at any arbitrary set of byte offsets including mid-header, is read back as the same frames in the same order with the same stream identifiers. This is the shim protocol's analogue of Property 3, and it is what makes a partial read on a real pipe a non-event.

### Property 43: Stream identifier spaces never collide

For any interleaving of node-allocated outbound identifiers and shim-allocated inbound identifiers, no identifier is ever assigned to two live streams. Asserted over the allocation rule rather than by running two radios.

### Property 44: A shim failure fails every open stream

For any set of open Shim_Streams, when the shim exits or declares an oversized payload, every stream returns an error and none blocks. This is what lets a Session rebind instead of hanging, so the property asserts the absence of a hang rather than a particular error value.

### Property 45: An oversized declared payload is refused without allocating

A Shim_Frame header declaring a length above the maximum is rejected before the payload is read, so a corrupt or hostile length cannot make the node allocate on demand.

### Property 46: Presence sources compose without losing observations

For any interleaving of observations from two Presence_Sources, expiry sweeps, and reads, the visible Peer list contains exactly one entry per fingerprint, lists every medium each Peer was seen on, and loses no observation that arrived before its expiry. Run under the race detector.

### Property 47: A malformed record is medium-independent

For any byte string that fails announcement validation, feeding it through the Bluetooth path produces the same malformed reasons and the same unchanged Peer list as feeding it through the LAN path. Prevents the two media drifting into different validation.

### Property 48: The verification code is derived, never carried

For any pair of identities, the code both sides derive is equal, and no encoded `PairingOffer` or `PairingDecision` frame contains the code's digits. The second half is the security-relevant one: it asserts the code is absent from the wire rather than merely that derivation agrees.

### Property 49: Pairing completes only on mutual confirmation

Over all four combinations of the two users' decisions, trust is recorded in exactly one — both confirmed — and in the other three no trust is recorded and the connection closes. Asserted clause by clause rather than against a reimplementation.

### Property 50: A mismatched key is reported apart from an untrusted peer

For any fingerprint already holding a key, an offer carrying a different key produces a key-mismatch report and never an untrusted-peer report, and records no trust.

### Property 51: Nothing but pairing precedes trust

For any message type other than pairing and key exchange, delivering it on a connection before trust exists leaves all Session and trust state untouched.

### Property 52: Selection resolves to the peer that was displayed

For any sequence of appearances and expiries between display and selection, a selection index either connects to the fingerprint shown at that index or reports that the peer is no longer visible. It never connects to a different peer.

### Property 53: An arriving message preserves the typed buffer

For any partially typed input and any arriving Message, the input buffer after the Message is displayed equals the buffer before it. The rendering may repaint; the buffer may not change.

### Property 54: Every interactive state returns to the picker

From every terminal edge — connect failure, pairing rejection, pairing expiry, peer-closed Session, user leave — the state machine reaches the Peer_Picker, and only an explicit quit reaches exit.

### Property 55: Interactive output carries no secrets

No rendered Chat_View line, notice, or failure report contains key material or any payload byte other than the text Message content the user themselves sent or received. Extends the parent design's Property 35 and 41 to the new surface.

### Manual verification

Two things cannot be automated here and are release procedures rather than tests:

- **Two-machine Bluetooth discovery, pairing, and messaging.** No CI host has two radios in range. The in-process fabric covers the logic; the radio needs two machines.
- **Bluetooth authorization behaviour.** Whether TCC prompts, denies, or inherits depends on the terminal and on prior grants on that machine.

---

## Failure Modes

| Failure | Detection | Reported as | Node continues |
| --- | --- | --- | --- |
| BT_Shim absent | `os.Stat` on the shim path | BT_Transport unavailable, naming the missing shim | yes, LAN only |
| Bluetooth authorization denied | shim reports `unauthorized` | BT_Transport unavailable, remediation names the terminal grant | yes, LAN only |
| Bluetooth radio off | shim reports `poweredOff` | BT_Transport unavailable, distinct reason | yes, LAN only |
| Shim crashes mid-session | node's read loop sees EOF | every stream fails; Sessions rebind | yes |
| Shim desynchronises | oversized declared length | shim torn down and restarted on next use | yes |
| Peer out of Bluetooth range | connect attempt times out at 3 s | connect failure naming each Transport tried | yes |
| Pairing rejected by either user | `PairingDecision` of 0 | pairing rejected; no trust recorded | yes |
| Pairing code expired | 120 s deadline | pairing expired; no trust recorded | yes |
| Offered key contradicts a stored one | trust store lookup | key mismatch, distinct from untrusted | yes |
| Multicast filtered on the network | no LAN observations | nothing; `peers add` is the documented escape | yes |

---

## Testing Strategy

The shim itself is the one part that cannot be tested from Go. Everything on the Go side is tested against `InMemoryBluetoothBridge` and the in-process `Fabric`, which already exist and already model the link MTU so the 512-byte chunk size is exercised rather than bypassed.

| Layer | Approach |
| --- | --- |
| Shim frame protocol | Property 42–45 against a pipe, no radio |
| Presence composition | Property 46–47 with two sources over one registry, under `-race` |
| Pairing exchange | Property 48–51 over the in-process fabric, both roles |
| Interactive state machine | Property 52–54 with scripted input and a fake registry; the state machine takes its input as an interface so no terminal is involved |
| Secret absence | Property 55 over rendered output |
| Shim behaviour on a real radio | manual, two machines, per release |

The interactive state machine is designed to be testable without a terminal: it reads lines from an interface and writes to an `io.Writer`, so the test drives it with a scripted script and asserts on captured output. That is the same shape as the existing status renderer test.

---

## Risks and Open Questions

1. **Two files instead of one.** The helper-process model puts the deliverable in tension with the parent spec's Requirement 12.2, which wants one self-contained executable. Resolving it means either embedding the shim with `go:embed` and extracting it on first run, or moving to the linked cgo shim of Option A. Neither is in this feature's scope. Recorded rather than solved.
2. **BLE throughput against the ranking figure.** The parent spec's 40 KiB/s for BT_Transport is a ranking constant, not a promise, and ranking only needs it to sort below LAN. But if measured goodput lands far below it, the transfer chunk timing of the parent spec's Requirement 7 may need revisiting. Measure before assuming.
3. **Terminal repainting for Requirement 8.3.** Reading input a rune at a time to keep the buffer known is more machinery than a line reader, and behaviour varies across terminals. If it proves fragile the fallback is to print arriving Messages above the prompt without repainting, which technically fails 8.3 and would need the requirement revisited rather than quietly dropped.
4. **Device identifier stability.** The design assumes the peripheral identifier a central sees is stable enough to reconnect with. If macOS rotates it, `Connect` after a rescan may need to re-resolve by fingerprint instead. Verify on two machines.
5. **Windows and Linux remain LAN-only.** Requirement 11.1 makes this explicit rather than aspirational, but it does mean the cross-platform story is unfinished, and a Linux user reading the README will find Bluetooth listed as a transport they cannot use.
