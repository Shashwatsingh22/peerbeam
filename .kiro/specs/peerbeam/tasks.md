# Implementation Plan: Peerbeam

## Overview

This plan builds Peerbeam bottom-up: the pure `internal/core` packages first (wire codec, discovery
bookkeeping, transport ranking and switching, session sequencing and queues, text, clipboard,
transfer, trust, crypto, reporting), then the `internal/platform` I/O adapters (LAN sockets, Bluetooth
bridge, clipboard commands, key and trust file stores), then the `internal/app` wiring and the
`cmd/peerbeam` CLI, and finally end-to-end integration and packaging.

Every pure component is implemented as plain functions or small `Clock`-injected structs so its
correctness properties can be exercised without a network. Property-based tests use
`pgregory.net/rapid` (`rapid.Check`) at a minimum of 100 iterations each, one test per property in the
design, and live in `*_test.go` files alongside the code they exercise per Go convention. Test
sub-tasks are marked with `*` and may be skipped for a faster MVP, but the design treats property
tests as central, so implementing them is strongly recommended.

Language: Go 1.23, built as a single statically linked binary with `go build`. The Bluetooth shim is
per-OS native code reached over cgo. This is fixed by the design; no language choice is open.

## Tasks

- [x] 1. Set up the Go module and package skeleton
  - Run `go mod init github.com/peerbeam/peerbeam` and set the `go 1.23` toolchain directive
  - Pin dependencies in `go.mod`: `github.com/spf13/cobra v1.8.1`, `golang.org/x/crypto v0.31.0`, and `pgregory.net/rapid v1.1.0` (test only); commit the resulting `go.sum`
  - Create the pure package layout under `internal/core` (codec, crypto, discovery, transport, session, text, clipboard, transfer, trust, report) with no imports from `net`, `os`, or sockets
  - Create the adapter layout under `internal/platform` (lan, bt, clip, store, share), the wiring package `internal/app`, and the entrypoint `cmd/peerbeam/main.go`
  - Create the `shim/` directory with `macos`, `windows`, and `linux` subdirectories for the cgo Bluetooth code
  - _Requirements: 12.2, 12.6, 12.7_

- [x] 2. Implement the wire codec (Message_Codec)
  - [x] 2.1 Implement `Frame`, `MessageType`, and codec constants
    - Create `internal/core/codec/frame.go` with the `Frame` struct (ProtocolVersion uint8, Type uint8, Sequence uint64, Payload []byte) and an `Equal` method using `bytes.Equal`
    - Create `internal/core/codec/messagetype.go` with the `MessageType` typed constants and `MessageTypeFromCode` returning `(MessageType, bool)`
    - Define `ProtocolVersion`, `HeaderBytes = 14`, `MaxPayloadBytes = 1_048_576`
    - _Requirements: 8.1_

  - [x] 2.2 Implement `EncodeFrame` with the fixed 14-byte big-endian header
    - Create `internal/core/codec/encoder.go` returning the tagged `EncodeResult` (either `Bytes` or `*PayloadTooLarge`)
    - Use `encoding/binary` big-endian writes; reject payloads over 1,048,576 bytes at encode time, naming the length and the maximum
    - _Requirements: 8.1, 8.9, 8.10_

  - [x] 2.3 Implement `FrameReader` incremental parsing with strict field-order validation
    - Create `internal/core/codec/reader.go` with a growable buffer, `Push(bytes []byte) ReadResult`, and `FlushIncomplete() *ReadResult`, holding an injected `Clock`
    - Validate protocol version, then type, then sequence, then payload length, in that order, returning the first failing field via the tagged `CodecError` (`UnsupportedVersion`, `PayloadTooLarge`, `FramingMismatch`)
    - Reject a declared length over 1 MiB at the header before buffering payload; return unrecognised type codes as parsed frames (not errors); enforce the 10-second payload timeout using the injected `Clock`
    - _Requirements: 8.2, 8.4, 8.5, 8.6, 8.7, 8.8, 8.11, 8.12_

  - [ ]* 2.4 Write property test for frame round trip
    - **Property 1: Frame round trip**
    - **Validates: Requirements 8.1, 8.2, 8.3**

  - [ ]* 2.5 Write property test for byte round trip and encoding determinism
    - **Property 2: Byte round trip and encoding determinism**
    - **Validates: Requirements 8.4, 8.9**

  - [ ]* 2.6 Write property test for stream framing under arbitrary segmentation
    - **Property 3: Stream framing under arbitrary segmentation**
    - **Validates: Requirements 8.2, 8.3**

  - [ ]* 2.7 Write property test for incomplete frames
    - **Property 4: Incomplete frames produce a framing error and leave sequence state untouched**
    - **Validates: Requirements 8.5, 8.12**

  - [ ]* 2.8 Write property test for header field-order validation
    - **Property 5: Header validation happens in field order and reports the first failure**
    - **Validates: Requirements 8.6, 8.7, 8.11**

  - [ ]* 2.9 Write property test for oversized payload rejection
    - **Property 6: Oversized payloads are rejected at encode time**
    - **Validates: Requirements 8.10**

  - [ ]* 2.10 Write property test for unrecognised message type skipping
    - **Property 7: Unrecognised message types are skipped and the stream continues**
    - **Validates: Requirements 8.8**

  - [ ]* 2.11 Write golden-bytes unit test for the wire format
    - Fixed frame in, hex-literal expected bytes out, to pin field layout against accidental reorder
    - _Requirements: 8.9_

- [x] 3. Checkpoint - codec complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement discovery bookkeeping (Discovery_Service core)
  - [x] 4.1 Implement announcement model, codec, and validation
    - Create `internal/core/discovery/announcement.go` (`Announcement` struct with json tags: DisplayName, Fingerprint, ProtocolVersion, Port) plus `Medium`, `PeerEndpoint`, `VisiblePeer`
    - Create `internal/core/discovery/announcementcodec.go` marshalling to/from JSON with `encoding/json`
    - Implement `CheckAnnouncement` returning the tagged `AnnouncementCheck` (`Valid` or `Malformed` reasons) for missing fields, a port outside 1..65535, or a display name over 64 UTF-8 characters
    - _Requirements: 1.1, 1.11_

  - [x] 4.2 Implement `PeerRegistry` as a bounded, fingerprint-keyed upsert
    - Create `internal/core/discovery/peerregistry.go` with `Observe`, `AddManual`, `Expire`, `Visible`, `MediaFor`, an injected `Clock`, and `MaxVisiblePeers = 64`
    - Upsert by fingerprint (single entry per fingerprint, merged media, most-recent address/port per medium); mark manual entries as manually supplied; validate manual host/port and leave the list unchanged on rejection naming address vs port; expire peers stale on every medium for >= 30 s
    - _Requirements: 1.2, 1.5, 1.6, 1.7, 1.8, 1.10_

  - [ ]* 4.3 Write property test for announcement validation and round trip
    - **Property 8: Announcement validation and round trip**
    - **Validates: Requirements 1.1, 1.11**

  - [ ]* 4.4 Write property test for the bounded fingerprint-keyed upsert
    - **Property 9: The visible Peer list is a bounded, fingerprint-keyed upsert**
    - **Validates: Requirements 1.2, 1.6, 1.7, 1.8**

  - [ ]* 4.5 Write property test for staleness-based expiry
    - **Property 10: Peers are removed exactly when every medium has gone stale**
    - **Validates: Requirements 1.5**

  - [ ]* 4.6 Write property test for invalid manual entries
    - **Property 11: Invalid manual entries change nothing**
    - **Validates: Requirements 1.10**

- [x] 5. Implement transport ranking and the connection ladder (Transport_Manager core, part 1)
  - [x] 5.1 Define `Transport` / `TransportConnection` interfaces and ranking constants
    - Create `internal/core/transport/transport.go` with both interfaces and the goodput/chunk constants (`LANExpectedGoodput`, `BTExpectedGoodput`, `LANChunkBytes = 65_536`, `BTChunkBytes = 512`)
    - _Requirements: 2.1, 7.10_

  - [x] 5.2 Implement `CandidateTransports` and `RankCandidates`
    - Create `internal/core/transport/ranker.go`: candidates are enabled transports whose medium the peer is visible on; rank descending by expected goodput with ties broken by ascending name via `sort.SliceStable`
    - _Requirements: 2.1, 2.2_

  - [x] 5.3 Implement the connection ladder
    - Create `internal/core/transport/ladder.go` with `ConnectLadder`, `AttemptRecord`, and the tagged `LadderResult` (`Connected`, `AllFailed`, `NoCandidate`)
    - Attempt each candidate once in rank order using a per-attempt `context.WithTimeout` of 3 s, one attempt open at a time, no retries; on total failure return an attempt record per candidate with a non-empty reason; return `NoCandidate` for the empty list
    - _Requirements: 2.3, 2.4, 2.5, 2.6, 3.8_

  - [x]* 5.4 Write property test for candidate selection and ranking
    - **Property 12: Candidate selection and ranking are deterministic and speed-ordered**
    - **Validates: Requirements 2.1, 2.2**

  - [x]* 5.5 Write property test for the connection ladder
    - **Property 13: The connection ladder attempts each candidate at most once and reports every attempt**
    - **Validates: Requirements 2.3, 2.4, 2.5, 2.6, 3.8**

- [x] 6. Implement switch decision, keepalive, and metrics (Transport_Manager core, part 2)
  - [x] 6.1 Implement `DecideSwitch` and its input/decision types
    - Create `internal/core/transport/switchpolicy.go` with `SwitchInputs`, the tagged `SwitchDecision` (`Stay`, `Upgrade`, `Rebind`, `GoDisconnected`), and the `UpgradeStability = 5s` / `UpgradeCooldown = 30s` constants
    - Encode the full rule table: pin overrides everything; unavailable-active rebinds to best candidate or disconnects; healthy upgrades only when strictly faster, stable 5 s, and 30 s since last change; else stay
    - _Requirements: 2.8, 2.10, 2.11, 3.3_

  - [x] 6.2 Implement `KeepaliveTracker` and `TransportMetrics`
    - Create `internal/core/transport/keepalive.go`: three-strike counter with `OnResponse`, `OnTimeout`, and `Misses`, marking unavailable on the third consecutive miss
    - Create `internal/core/transport/metrics.go`: sample measured goodput and RTT once per second, retain only the latest of each
    - _Requirements: 3.1, 3.2, 2.7_

  - [x]* 6.3 Write property test for the switch decision rule table
    - **Property 14: The switch decision follows exactly one rule table**
    - **Validates: Requirements 2.8, 2.10, 2.11, 3.3**

  - [x]* 6.4 Write property test for keepalive strike counting
    - **Property 16: Keepalive marks a Transport unavailable on exactly the third consecutive miss**
    - **Validates: Requirements 3.1, 3.2**

  - [x]* 6.5 Write unit test for metrics retention
    - Sampling keeps only the most recent goodput and RTT values
    - _Requirements: 2.7_

- [x] 7. Checkpoint - discovery and transport logic complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement session identity, sequencing, reordering, and queues (Session core)
  - [x] 8.1 Implement `SessionId`, `SessionRegistry`, and admission
    - Create `internal/core/session/sessionid.go` and `internal/core/session/registry.go` with `MaxConcurrentSessions = 8` and a `sync.Mutex` guarding only the registry map, never held across I/O
    - Implement the tagged `SessionAdmission` (`Admitted`, `LimitReached`, `PeerNotTrusted`, `KeyMismatch`); reject a 9th session naming the limit; give each session a distinct id and key material and its own channels; leave other sessions unchanged on close
    - _Requirements: 4.1, 4.2, 4.3, 4.9_

  - [x] 8.2 Implement `SequenceTracker` and `ReorderBuffer`
    - Create `internal/core/session/sequencetracker.go`: monotonic outbound assignment via `NextSequence`, inbound duplicate detection via `AcceptInbound`
    - Create `internal/core/session/reorderbuffer.go`: present in ascending sequence order, hold a Message following a gap for at most 10 s (injected `Clock`) then release via `Offer`/`DrainExpired`
    - _Requirements: 5.1, 5.7, 5.10_

  - [x] 8.3 Implement `OutboundQueue` for the disconnected state
    - Create `internal/core/session/outboundqueue.go` with `QueueByteLimit = 64 MiB` and `QueueRetention = 10m`
    - `Submit` rejects over-budget submissions via the tagged `QueueResult` (`Rejected` carrying the limit) leaving the queue unchanged; `DrainForFlush` returns retained messages in ascending sequence order; `DiscardExpired` drops messages past retention and returns their sequence numbers
    - _Requirements: 3.6, 3.7, 3.9, 3.10_

  - [x] 8.4 Implement group send fan-out
    - Create `internal/core/session/groupsend.go` with the tagged `DeliveryOutcome` and `SendToGroup`: one goroutine per selected peer under a single 10 s `context.WithTimeout` and a `sync.WaitGroup`, exactly one outcome per peer, each active session consuming its own next sequence number, inactive peers reported not delivered with their message queued
    - _Requirements: 4.4, 4.5, 4.7, 4.8_

  - [x]* 8.5 Write property test for session bounds and isolation
    - **Property 18: Sessions are bounded and mutually isolated**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.9**

  - [x]* 8.6 Write property test for group send outcomes
    - **Property 19: A group send produces exactly one outcome per selected Peer**
    - **Validates: Requirements 4.4, 4.5, 4.7, 4.8**

  - [x]* 8.7 Write property test for presentation ordering
    - **Property 22: Presentation is ordered, gap-tolerant, and duplicate-free**
    - **Validates: Requirements 5.7, 5.10**

  - [x]* 8.8 Write property test for the disconnected outbound queue
    - **Property 17: The disconnected outbound queue respects its budget, order, and retention**
    - **Validates: Requirements 3.6, 3.7, 3.9, 3.10**

- [x] 9. Implement text validation and inbound disposition (TextService core)
  - [x] 9.1 Implement text size validation and strict UTF-8 decoding
    - Create `internal/core/text/validation.go` with `TextMinBytes`/`TextMaxBytes`, the tagged `TextCheck` (`Valid`, `OutOfRange`, `InvalidUTF8`), and `DecodeStrictUTF8` using `utf8.Valid` rather than a silently repairing `string()` conversion
    - Accept 1..65,536 UTF-8 bytes; reject out-of-range submissions naming the range without sending or advancing the sequence number
    - _Requirements: 5.1, 5.2, 5.8_

  - [x] 9.2 Implement `DisposeInboundText`
    - Extend `internal/core/text/validation.go` (or add `internal/core/text/inbound.go`) with the tagged `InboundTextDisposition` (`Display`, `DuplicateDiscard`, `WithholdWithError`, `Incomplete`)
    - Always acknowledge with the exact sequence number; display only when content, sender name, and timestamp are all present and the payload is valid UTF-8 and <= 65,536 bytes; otherwise withhold and either return an error naming the sequence and fault or record an incomplete event naming the missing items; keep the session active
    - _Requirements: 5.3, 5.4, 5.5, 5.6, 5.9_

  - [x]* 9.3 Write property test for symmetric size validation
    - **Property 20: Text size validation is symmetric and side-effect free**
    - **Validates: Requirements 5.1, 5.2, 5.8**

  - [x]* 9.4 Write property test for inbound text disposition
    - **Property 21: Inbound text is always acknowledged and displayed only when valid and complete**
    - **Validates: Requirements 5.3, 5.4, 5.5, 5.6, 5.9**

- [x] 10. Implement clipboard policy and part framing (Clipboard_Service core)
  - [x] 10.1 Implement clipboard send validation and part split/join
    - Create `internal/core/clipboard/parts.go` with `SplitClipboard`/`JoinClipboard` (4-byte part header, 524,288-byte parts) and `ClipboardMaxBytes = 1 MiB`, `ClipboardPartBytes = 512 KiB`
    - Implement clipboard send validation: accept 1..1,048,576 UTF-8 bytes; reject empty clipboard as unsupported content type and over-limit content naming the 1 MiB limit, sending nothing and leaving the clipboard unchanged
    - _Requirements: 6.1, 6.7, 6.8, 6.11_

  - [x] 10.2 Implement `DisposeInboundClipboard` and the pending-entry lifecycle
    - Create `internal/core/clipboard/policy.go` with `ClipboardSessionState`, `PendingClipboardEntry`, and the tagged `ClipboardDisposition` (`ApplyNow`, `HoldPending`, `DiscardAsEcho`, `Reject`)
    - Auto-apply replaces the whole clipboard; disabled auto-apply holds one pending entry per session (discarding any earlier one) and prompts with sender name and timestamp; confirm within 10 min applies and clears; decline or timeout clears without changing the clipboard; reject over-limit or invalid-UTF-8 naming the sequence; suppress echoes matching the last applied or last sent digest
    - _Requirements: 6.2, 6.3, 6.4, 6.5, 6.6, 6.9, 6.10_

  - [x]* 10.3 Write property test for clipboard send validation
    - **Property 23: Clipboard send validation**
    - **Validates: Requirements 6.1, 6.7, 6.11**

  - [x]* 10.4 Write property test for clipboard part round trip
    - **Property 24: Clipboard part split and join round trip**
    - **Validates: Requirements 6.8**

  - [x]* 10.5 Write property test for inbound clipboard disposition and pending lifecycle
    - **Property 25: Inbound clipboard disposition and the pending-entry lifecycle**
    - **Validates: Requirements 6.2, 6.3, 6.4, 6.9, 6.10**

  - [x]* 10.6 Write property test for clipboard echo suppression
    - **Property 26: Clipboard echo suppression prevents loops**
    - **Validates: Requirements 6.5, 6.6**

- [x] 11. Checkpoint - session, text, and clipboard logic complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Implement transfer chunk planning and progress (Transfer_Service core)
  - [x] 12.1 Implement `PlanChunks`, `ChunkRef`, `TransferOffer`, and `TransferId`
    - Create `internal/core/transfer/chunkplanner.go`: slice `[fromOffset, fileSize)` into ascending chunks with absolute byte offsets, indices 0..n-1, a consistent total, and only a final short chunk; usable for first leg, resume, and re-slice at a new chunk size
    - Create `internal/core/transfer/transferstate.go` for `TransferOffer` (TransferId, FileName, ByteSize, SHA256) and the file-size constants (`FileMinBytes = 1`, `FileMaxBytes = 64 GiB`)
    - _Requirements: 7.1, 7.2, 7.8, 7.10, 3.5_

  - [x] 12.2 Implement `TransferProgress` and `ResendTracker`
    - Create `internal/core/transfer/transferstate.go` additions for `TransferProgress`: merged acknowledged offset ranges, `ContiguousAckedThrough`, `AcknowledgedBytes`, `OnAck`
    - Create `internal/core/transfer/resendtracker.go`: per-chunk resend counters via `RegisterResend` returning `(attempt, ok)`, at most `MaxResendAttempts = 5`, stopping a transfer after exhaustion naming the transfer id and chunk index and retaining resumable state for 10 min
    - Implement integrity check: compute SHA-256 of assembled content with `crypto/sha256` and compare to the offer; on mismatch report both digests and discard, or report the retained location if it cannot be discarded
    - Implement offer/cancel outcomes: no chunk sent for a declined offer, a 60 s offer timeout, or a file size out of range (naming measured size and range); cancel stops chunks and instructs the receiver to release partial content
    - _Requirements: 7.3, 7.4, 7.5, 7.6, 7.7, 7.9, 7.11, 7.12, 7.13_

  - [x]* 12.3 Write property test for the chunk plan
    - **Property 27: The chunk plan covers a file exactly once and reassembles to the original bytes**
    - **Validates: Requirements 7.1, 7.2, 7.4, 7.8, 7.10, 3.5**

  - [x]* 12.4 Write property test for corrupted-transfer detection
    - **Property 28: Corrupted transfers are always caught and the content is released**
    - **Validates: Requirements 7.5, 7.6**

  - [x]* 12.5 Write property test for transfer termination and resumable state
    - **Property 29: Transfer termination stops Chunk sending and preserves resumable state**
    - **Validates: Requirements 7.7, 7.9, 7.11, 7.12, 7.13**

  - [x]* 12.6 Write unit tests for progress report shape and undeletable-file integrity failure
    - Progress report carries transfer id, acknowledged bytes, total size, and goodput; integrity failure with an undeletable file reports the retained location
    - _Requirements: 7.3, 7.6_

- [x] 13. Implement trust model and verification code (trust core)
  - [x] 13.1 Implement `TrustedPeer`, fingerprint, and `VerificationCode`
    - Create `internal/core/trust/trustmodel.go` (`TrustedPeer` struct and the `KeyStore`/`TrustStore` interfaces) and `internal/core/trust/fingerprint.go`
    - Create `internal/core/crypto/verificationcode.go`: exactly 6 decimal digits (with leading zeros) derived from both public keys sorted with `bytes.Compare` so both nodes compute the same code, valid for `VerificationCodeValidity = 120s`
    - _Requirements: 9.3, 9.4_

  - [x] 13.2 Implement pairing outcome and session admission logic over the trust model
    - Implement pairing success/failure: add both keys on mutual confirmation within 120 s keeping one entry per fingerprint; on mismatch or timeout discard the received key, add nothing, leave existing entries unchanged, and name the affected peer
    - Implement admission decisions: admit only trusted, byte-identical keys; reject untrusted peers with a pairing prompt and no payload delivery; reject a differing key as a mismatch leaving the stored key unchanged; removing a peer closes its session and rejects future requests; while key/trust store is failed, reject every request naming the failing step
    - _Requirements: 9.2, 9.5, 9.6, 9.7, 9.8, 9.11_

  - [x]* 13.3 Write property test for the verification code
    - **Property 30: The verification code is symmetric, deterministic, and exactly 6 digits**
    - **Validates: Requirements 9.3**

  - [x]* 13.4 Write property test for failed pairing
    - **Property 32: Failed pairing changes nothing**
    - **Validates: Requirements 9.5**

  - [x]* 13.5 Write property test for session admission
    - **Property 33: Session admission accepts only trusted, byte-identical keys**
    - **Validates: Requirements 9.2, 9.6, 9.7, 9.8, 9.11**

- [x] 14. Implement session crypto (SessionCrypto core)
  - [x] 14.1 Implement HKDF and the authenticated handshake
    - Create `internal/core/crypto/hkdf.go` (HKDF-SHA256 over `crypto/hmac` + `crypto/sha256`, or `golang.org/x/crypto/hkdf`) and `internal/core/crypto/handshake.go`
    - Generate ephemeral X25519 keys with `golang.org/x/crypto/curve25519`, exchange fingerprint + ephemeral public key + Ed25519 signature (`crypto/ed25519`) over the fixed transcript, verify the signature and the stored long-term key, run ECDH, and derive two directional `SessionKeys` per session (fresh, never reused)
    - _Requirements: 10.1, 10.5_

  - [x] 14.2 Implement `SessionCrypto` seal/open with derived nonces
    - Create `internal/core/crypto/sessioncrypto.go`: ChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`) with the frame header as AAD and a 12-byte nonce derived from direction byte + sequence
    - `Seal` produces ciphertext with the 16-byte tag; `Open` returns `(nil, false)` on tag failure so the caller discards the message, closes the session, reports an authentication failure, and leaves sequence state unchanged; nothing but key-exchange types is processed pre-handshake, and a handshake past its 5 s deadline abandons establishment leaving no session
    - _Requirements: 10.2, 10.3, 10.4, 10.7, 10.8, 10.9, 11.5_

  - [x]* 14.3 Write property test for the handshake key binding
    - **Property 34: The handshake binds Session keys to both long-term keys and produces fresh keys**
    - **Validates: Requirements 10.1, 10.5**

  - [x]* 14.4 Write property test for sealed payloads
    - **Property 35: Sealed payloads round trip, leak no plaintext, and reject every tamper**
    - **Validates: Requirements 10.2, 10.3, 10.7**

  - [x]* 14.5 Write property test for pre-handshake gating
    - **Property 36: Nothing is processed before the handshake completes**
    - **Validates: Requirements 10.8, 10.9, 11.5**

- [x] 15. Implement reporting and visibility (report core)
  - [x] 15.1 Implement event, failure, status, and transport-change types
    - Create `internal/core/report/evententry.go` (`EventType`, `EventEntry` with no content field, `MessageTrace` limited to type/sequence/length), `internal/core/report/failure.go`, `internal/core/report/statusline.go` with the all-or-nothing `BuildStatusLine` returning the tagged `StatusLine`, and `TransportChangeReason`
    - _Requirements: 10.6, 13.1, 13.2, 13.3, 13.5_

  - [x] 15.2 Implement the `Describe` error-to-failure mapping and degraded/stall detection
    - Create `internal/core/report/describe.go`: a `switch` over the closed set of `AppError` kinds mapping every variant to a `Failure` with a non-empty operation, peer, reason, and remediation, with a `default` panic under test plus an `exhaustive` linter check; a transport connection failure names each attempted transport in order and a switch names both transports; other sessions untouched
    - Create `internal/core/report/failure.go` (or a `detectors.go`) with degraded-throughput and stall detection over a 10-second window of per-second samples / acknowledged byte counts, continuing the transfer and keeping the session active
    - _Requirements: 2.5, 2.9, 11.8, 11.9, 13.4, 13.6, 13.7_

  - [x]* 15.3 Write property test for the persistent trust store
    - **Property 31: The trust store persists faithfully, holds one entry per fingerprint, and never loses a key silently**
    - **Validates: Requirements 9.4, 9.9, 9.10, 9.11**

  - [x]* 15.4 Write property test for secret-free logs and reports
    - **Property 37: Logs and reports never contain secrets**
    - **Validates: Requirements 10.6, 13.5**

  - [x]* 15.5 Write property test for degraded/stall detection
    - **Property 38: A continuous below-target window is detected exactly**
    - **Validates: Requirements 11.8, 11.9, 13.6**

  - [x]* 15.6 Write property test for all-or-nothing status rendering
    - **Property 39: Session status is rendered all-or-nothing**
    - **Validates: Requirements 13.1, 13.2**

  - [x]* 15.7 Write property test for complete failure reports
    - **Property 40: Every failure report is complete and harms no other Session**
    - **Validates: Requirements 2.5, 2.9, 13.4, 13.7**

  - [x]* 15.8 Write property test for the closed set of transport-change reasons
    - **Property 41: A Transport change is reported with a closed set of reasons**
    - **Validates: Requirements 13.3**

  - [x]* 15.9 Write property test for transport-change session identity preservation
    - **Property 15: A Transport change preserves Session identity**
    - **Validates: Requirements 2.9, 3.4, 10.4**

- [x] 16. Checkpoint - the entire `internal/core` is complete and property-tested
  - Ensure all tests pass, ask the user if questions arise.

- [x] 17. Implement the LAN platform adapter
  - [x] 17.1 Implement `LanTransport` over the `net` package
    - Create `internal/platform/lan/transport.go` implementing `Transport`/`TransportConnection` with `net.TCPConn`/`net.TCPListener`, LAN goodput, and the 64 KiB chunk size
    - _Requirements: 2.1, 7.10_

  - [x] 17.2 Implement the UDP multicast beacon
    - Create `internal/platform/lan/beacon.go`: a `net.UDPConn` joined to `239.255.41.7:45771` via `net.ListenMulticastUDP` on every up interface, publish once at startup and every 5 s via a `time.Ticker`, feed received datagrams through `CheckAnnouncement` into `PeerRegistry`, and sweep expiry every 2 s
    - _Requirements: 1.1, 1.3, 1.9_

  - [x]* 17.3 Write integration test for LAN discovery latency
    - Two in-process nodes over a `LoopbackLanTransport` reach each other's visible peer list within the discovery window, under standard `go test`
    - _Requirements: 1.3_

- [x] 18. Implement the Bluetooth, clipboard, and share-sheet platform adapters
  - [x] 18.1 Implement `BluetoothBridge` and `BtTransport`
    - Create `internal/platform/bt/bridge.go` (re-exporting the `core` interface + `DiscoveredBtPeer` wiring), `internal/platform/bt/transport.go` (`BtTransport` with BT goodput and 512-byte chunk size), and `internal/platform/bt/shimbridge.go` (`ShimBluetoothBridge`) speaking the length-prefixed frame format over the helper process stdio with `os/exec` (Option B), plus an `InMemoryBluetoothBridge` test double piping bytes over channels
    - Report `BT_Transport` unavailable when no bridge is available; leave a cgo note in `bridge.go` for the Option A linked shim path
    - _Requirements: 1.4, 2.1, 7.10, 12.3_

  - [x] 18.2 Implement `CommandClipboardPort` per OS
    - Create `internal/platform/clip/commandport.go` implementing `ClipboardPort` by shelling out with `os/exec` to pbpaste/pbcopy (macOS), Get-Clipboard/clip.exe (Windows), wl-paste/wl-copy with an xclip fallback (Linux); report unsupported when no tool is present
    - _Requirements: 6.1, 6.2_

  - [x] 18.3 Implement the macOS share sheet for AirDrop handoff
    - Create `internal/platform/share/macsharesheet.go` invoking the macOS cgo shim (`NSSharingServicePicker`) to open the share picker with the file selected within 5 s, keeping sessions unchanged; reject on non-macOS with a build-tagged stub, and reject a missing/unreadable file naming the file and reason
    - _Requirements: 12.4, 12.5, 12.9_

  - [x]* 18.4 Write unit tests for the per-OS clipboard adapters
    - Each adapter round-trips text against its real command line tool
    - _Requirements: 6.1, 6.2_

  - [x]* 18.5 Write unit tests for the platform capability branches
    - Bluetooth-unavailable startup (LAN only), no-transport startup, non-macOS AirDrop rejection, missing/unreadable-file AirDrop rejection
    - _Requirements: 12.3, 12.5, 12.8, 12.9_

- [x] 19. Implement the file key store and trust store platform adapters
  - [x] 19.1 Implement `FileKeyStore` and cross-platform permissions
    - Create `internal/platform/store/keystore.go` and `internal/platform/store/permissions.go` (+ `permissions_windows.go`): generate the Ed25519 identity on first run, store `identity.key` owner-only via `os.Chmod(path, 0o600)` on macOS/Linux and a Windows ACL via `golang.org/x/sys/windows` in `permissions_windows.go`, and return an error naming the failing step so the node rejects sessions until it succeeds
    - _Requirements: 9.1, 9.2_

  - [x] 19.2 Implement `FileTrustStore` with an integrity tag
    - Create `internal/platform/store/truststore.go`: `trusted.json` (via `encoding/json`) with an HMAC-SHA256 tag over canonical entry bytes; load before the first session request, hold >= 32 entries and one per fingerprint, and on a failed tag check report a trust store failure, leave the file unmodified, and block every session request; delete a key only on user removal
    - _Requirements: 9.9, 9.10, 9.11_

- [x] 20. Checkpoint - platform adapters complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 21. Implement the node wiring and CLI (app and cmd)
  - [x] 21.1 Implement the `NewPeerNode` constructor and concurrency scaffolding
    - Create `internal/app/peernode.go`: build the root `context.Context` via `context.WithCancel` and a `sync.WaitGroup`, wire discovery/pairing/session registry/transport manager/services, and give each session a child context with reader, writer (control channel preferred over bulk via a non-blocking `select`), keepalive, and metrics goroutines plus chunk pipelining
    - _Requirements: 4.2, 4.6_

  - [x] 21.2 Implement the cobra command tree
    - Create `cmd/peerbeam/main.go` (builds the cobra root command) and `internal/app/commands.go` with one command per capability (peers, peers add, pair, trust list/remove, connect, disconnect, pin, send, clip send/auto/sync/pending, file send/resume/cancel, status, log tail, airdrop), no graphical surface
    - _Requirements: 12.6_

  - [x] 21.3 Implement the status renderer
    - Create `internal/app/statusrenderer.go` rendering per-session status via `BuildStatusLine` and refreshing every second with a `time.Ticker`, showing transport-change reports from the closed reason set
    - _Requirements: 13.1, 13.2, 13.3_

  - [x]* 21.4 Write unit test for CLI command coverage and writer priority
    - Every capability in Requirements 1-11 has a command; with the bulk channel saturated, a control message is written next by `writerLoop`
    - _Requirements: 4.6, 12.6_

- [ ] 22. End-to-end integration and cross-compiled packaging
  - [ ] 22.1 Configure `go build` cross-compilation for the release targets
    - Add a build script (or `Makefile`) invoking `go build` for `darwin/arm64`, `darwin/amd64`, `windows/amd64`, `linux/amd64`, and `linux/arm64` with `CGO_ENABLED=1` and the appropriate cross toolchain per target for the Bluetooth shim, producing a single file <= 50 MiB per target
    - _Requirements: 12.1, 12.2, 12.7_

  - [ ]* 22.2 Write end-to-end integration tests over loopback and the in-memory bridge
    - Under standard `go test`, using `LoopbackLanTransport` + `InMemoryBluetoothBridge`: pair/connect/send text with acknowledgement; send a large file over loopback and verify the digest and per-window goodput; kill LAN mid-transfer and verify rebind keeps id and keys and resumes from the acknowledged offset at the 512-byte chunk size; eight concurrent sessions with one transfer measuring other-session text latency and sampling resident memory; restart and confirm the trust store loads before the first session request
    - _Requirements: 3.4, 3.5, 4.6, 9.10, 11.2, 11.6_

  - [ ]* 22.3 Write smoke tests on the release artifacts
    - Single file under 50 MiB reaching ready state within 5 s in an empty container; owner-only `identity.key` after first run; beacon republish <= 10 s, keepalive 5 s, chunk sizes 65,536 and 512
    - _Requirements: 1.9, 3.1, 7.10, 9.1, 12.1, 12.2, 12.7_

- [ ] 23. Final checkpoint - ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP. Because this design
  makes property-based testing central, skipping the property test sub-tasks is not recommended.
- Each task references specific requirement sub-clauses for traceability.
- Each property test sub-task maps to exactly one property from the design's Correctness Properties
  section, uses `pgregory.net/rapid` (`rapid.Check`) at a minimum of 100 iterations, and lives in a
  `*_test.go` file alongside the code it exercises. A `Clock` is injected (a `manualClock` in tests)
  so time-dependent properties run instantly against a mutable clock instead of sleeping.
- Checkpoints ensure incremental validation at module boundaries.
- The `internal/core` packages are built and fully property-tested before any I/O adapter, so every
  correctness property is exercised without a network. Platform adapters then implement the interfaces
  `core` declares, and `internal/app` plus `cmd/peerbeam` wire them together.
- Timing and hardware measurements on real radios or reference networks (Requirements 11.1, 11.3,
  11.4) require documented manual procedures per release and are not automatable as coding tasks, so
  they are out of scope for this task list.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["2.1"] },
    { "id": 1, "tasks": ["2.2", "2.3"] },
    {
      "id": 2,
      "tasks": [
        "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11",
        "4.1", "5.1", "8.1", "8.2", "8.3", "9.1", "10.1", "12.1", "13.1", "14.1", "15.1"
      ]
    },
    {
      "id": 3,
      "tasks": [
        "4.2", "5.2", "5.3", "6.1", "6.2", "8.4",
        "9.2", "10.2", "12.2", "13.2", "14.2", "15.2"
      ]
    },
    {
      "id": 4,
      "tasks": [
        "4.3", "4.4", "4.5", "4.6", "5.4", "5.5", "6.3", "6.4", "6.5",
        "8.5", "8.6", "8.7", "8.8", "9.3", "9.4", "10.3", "10.4", "10.5", "10.6",
        "12.3", "12.4", "12.5", "12.6", "13.3", "13.4", "13.5",
        "14.3", "14.4", "14.5", "15.3", "15.4", "15.5", "15.6", "15.7", "15.8", "15.9"
      ]
    },
    { "id": 5, "tasks": ["17.1", "18.1", "18.2", "18.3", "19.1", "19.2"] },
    { "id": 6, "tasks": ["17.2", "17.3", "18.4", "18.5"] },
    { "id": 7, "tasks": ["21.1", "21.2", "21.3"] },
    { "id": 8, "tasks": ["21.4", "22.1"] },
    { "id": 9, "tasks": ["22.2", "22.3"] }
  ]
}
```
