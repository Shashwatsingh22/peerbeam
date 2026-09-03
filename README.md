# Peerbeam

Move text, clipboard content, and files between your own machines. Peerbeam finds your other
machines on the local network or over Bluetooth, pairs with them once, then sends over whichever
transport is currently fastest — falling back automatically when one goes away.

One static binary per platform. No server, no account, no runtime to install. The command line is
the only interface.

```
peerbeam peers                          # who is around
peerbeam pair <fingerprint>             # trust a machine, once
peerbeam send <fingerprint> --text "hi" # then just use it
```

---

## Project status

The protocol core is complete and heavily tested. Some of the top-level plumbing is not.

**Working end to end:** peer discovery, the encrypted session handshake, session admission and the
8-session limit, text messaging with acknowledgement and ordering, clipboard apply and echo
suppression, transport ranking and failover, the trust store, status reporting, and the event log.
An end-to-end suite runs two nodes in one process over a loopback transport and moves real text
and file chunks through the production code path, including rebinding and eight concurrent
sessions. Those tests seed both trust stores directly, which is precisely the gap below.

**Not built yet**, and worth knowing before you try it on two real machines:

| Gap | Effect |
| --- | --- |
| The pairing wire exchange | `peerbeam pair` cannot complete a first pairing between two machines. The trust model, code derivation, and confirmation logic are all done and tested; the exchange that carries the peer's public key over a connection is not. |
| The transfer sender loop | `file send` reports a real chunk plan and stops. `file resume` and `file cancel` print confirmations without driving a transfer. The chunk planner, progress tracking, resend ceiling, and integrity check are all implemented and tested. |
| The Bluetooth native shim | `shim/macos`, `shim/windows`, and `shim/linux` contain no native code, so Bluetooth reports itself unavailable on every real host and nodes run LAN-only. This is a supported, reported startup state — not a crash. |

So today Peerbeam is a working LAN peer-to-peer node with a complete protocol implementation and a
CLI whose discovery, session, text, clipboard, trust, and status commands do real work.

---

## Install

Requires Go 1.23 or later. Four Go modules are fetched automatically at build time — cobra for the
command tree, `x/crypto` for X25519 and ChaCha20-Poly1305, `x/sys` for Windows ACLs, and rapid for
the property tests. Nothing has to be installed on the machine that runs the binary.

```sh
git clone https://github.com/Shashwatsingh22/peerbeam.git
cd peerbeam
make build          # produces ./peerbeam in the working tree
```

`make build` leaves the binary in the repo, so run it as `./peerbeam`. A bare `peerbeam` will not
be found — the current directory is not on your PATH, and it should not be.

To use the short form shown throughout this README, install it onto your PATH instead:

```sh
make install        # builds into GOBIN, or GOPATH/bin if GOBIN is unset
```

That prints where the binary landed and, if that directory is not on your PATH, the exact line to
add. On a default Go setup with zsh:

```sh
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc && source ~/.zshrc
```

Cross-compiled release binaries for all five supported targets:

```sh
make release        # writes dist/peerbeam-<os>-<arch>, checks each against the 50 MiB ceiling
```

| Target | Notes |
| --- | --- |
| `darwin/arm64`, `darwin/amd64` | macOS 13 or later |
| `windows/amd64` | Windows 11 |
| `linux/amd64`, `linux/arm64` | Ubuntu 22.04 or later |

Each artifact is a single self-contained executable of roughly 6 MiB and needs nothing but itself.

---

## Getting started

### 1. See who is around

```sh
peerbeam peers
```

```
NAME         FINGERPRINT         VERSION  MEDIA  SOURCE
desktop      3f8a1c04e2b7d915... 1        LAN    discovered
```

Peers announce themselves every 5 seconds on the local network and drop off the list 30 seconds
after they go quiet. If multicast is filtered on your network, add a peer by address instead:

```sh
peerbeam peers add 192.168.1.42 45770
```

### 2. Pair, once

Pairing exchanges long-term keys so both machines recognise each other from then on. Run it on
both machines and compare the 6-digit code:

```sh
peerbeam pair 3f8a1c04e2b7d915...          # shows the code
peerbeam pair 3f8a1c04e2b7d915... --confirm # if the codes match
peerbeam pair 3f8a1c04e2b7d915... --reject  # if they do not
```

The code is never sent over the network. Both machines derive it independently from the two public
keys, so an attacker who controls the network cannot make them agree. It is valid for 2 minutes.

> **Note:** the wire half of this exchange is not implemented yet, so a first pairing between two
> real machines cannot complete. See [Project status](#project-status).

### 3. Connect and use it

```sh
peerbeam connect 3f8a1c04e2b7d915...
peerbeam send    3f8a1c04e2b7d915... --text "the link I meant to send you"
peerbeam clip send 3f8a1c04e2b7d915...
peerbeam file send 3f8a1c04e2b7d915... ~/Downloads/build.tar.gz
peerbeam status --watch
```

`status` shows one row per session and refreshes every second:

```
PEER      TRANSPORT      GOODPUT     RTT
desktop   LAN_Transport  38.2 MiB/s  3 ms
laptop    BT_Transport   39.1 KiB/s  84 ms
```

A row shows all four values or none of them. A session that has not measured its goodput yet reads
`pending` rather than showing a misleading `0 B/s`.

### Send to several machines at once

```sh
peerbeam send fp1 fp2 fp3 --text "deploying in 5"
```

Up to 8 peers. Each gets its own outcome, all within 10 seconds; a peer that is offline has the
message queued for when it comes back.

### Clipboard sharing

```sh
peerbeam clip send <fingerprint>              # push this machine's clipboard once
peerbeam clip auto <fingerprint> on           # apply what arrives, without asking
peerbeam clip sync <fingerprint> on           # keep pushing changes while connected
peerbeam clip pending show    <fingerprint>   # what is waiting for a decision
peerbeam clip pending accept  <fingerprint>
peerbeam clip pending decline <fingerprint>
```

Both `auto` and `sync` are off by default: nothing writes your clipboard and nothing leaves the
machine until you ask. With `sync` on in both directions, content is exchanged once and then stops —
each side suppresses content it just applied or just sent, so the two machines cannot bounce a
clipboard back and forth.

### Pinning a transport

```sh
peerbeam pin <fingerprint> BT_Transport   # stay on Bluetooth, do not switch
peerbeam pin <fingerprint> --clear        # resume automatic switching
```

A pinned session is never moved by the ranking. If the pinned transport goes away the session goes
to a disconnected state rather than switching, and says so.

### Trust management

```sh
peerbeam trust list
peerbeam trust remove <fingerprint>   # closes any session and refuses future ones
```

### macOS AirDrop handoff

```sh
peerbeam airdrop ~/Documents/contract.pdf
```

Opens the system share sheet with the file selected. This is a manual handoff — no public API lets
an application pick the AirDrop recipient, so a person does. On any other platform the command
refuses and says so. Active sessions are untouched either way.

---

## Command reference

| Command | What it does |
| --- | --- |
| `peers` | List visible peers with their media and protocol support |
| `peers add <host> <port>` | Add a peer by address, bypassing discovery |
| `pair <fingerprint>` | Show the verification code; `--confirm` / `--reject` to decide |
| `trust list` | List trusted peers with full fingerprints |
| `trust remove <fingerprint>` | Stop trusting a peer, closing its session |
| `connect <fingerprint>` | Open a session over the fastest available transport |
| `disconnect <fingerprint>` | Close one session, leaving the others alone |
| `pin <fingerprint> [transport]` | Pin to `LAN_Transport` or `BT_Transport`; `--clear` releases |
| `send <fingerprint>... --text <s>` | Send text to one peer or up to 8 |
| `clip send <fingerprint>...` | Push the clipboard |
| `clip auto <fingerprint> on\|off` | Automatic apply of received clipboard content |
| `clip sync <fingerprint> on\|off` | Continuous clipboard sync |
| `clip pending accept\|decline\|show <fingerprint>` | Decide on held clipboard content |
| `file send <fingerprint> <path>` | Send a file, verified with SHA-256 |
| `file resume <transfer-id>` | Resume within 10 minutes of an interruption |
| `file cancel <transfer-id>` | Stop a transfer and release the partial file |
| `status` | Per-session status; `--watch` redraws every second |
| `log tail` | Recent session, transport, and transfer events |
| `airdrop <path>` | macOS share sheet handoff |

Global flags:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--name` | this machine's host name | Display name published to peers |
| `--state-dir` | `~/.peerbeam` | Where `identity.key` and `trusted.json` live |
| `--port` | `0` (OS chooses) | TCP listening port |

Every failure prints the failing operation, the affected peer, the reason, and one thing you can do
about it:

```
$ peerbeam airdrop /no/such/file
hand off to AirDrop failed for laptop: cannot hand off /no/such/file: the file does not exist
  try: check that the path is correct and the file is readable, then try again
```

---

## How it works

### The organising idea

**All decision logic is pure; all I/O sits behind narrow interfaces.** Ranking transports,
validating announcements, slicing a file into chunks, deciding whether to switch transports,
reordering messages, enforcing queue limits, and encoding wire frames are plain functions over
plain data. Sockets, Bluetooth, the clipboard, and the filesystem are reached through small
interfaces that get real implementations in production and in-process fakes in tests.

That split is why the correctness properties can be checked without a network, and why the
end-to-end tests can run eight nodes in one process with no ports to collide over.

```
                 ┌──────────────────────────────────────────┐
   CLI (cobra) ──▶│  internal/app — wiring, one constructor  │
                 └──────────────┬───────────────┬───────────┘
                                │               │
                   ┌────────────▼──────┐   ┌────▼────────────────────┐
                   │  internal/core    │   │  internal/platform      │
                   │  pure decisions   │◀──│  I/O adapters           │
                   │  no net, no os    │   │  sockets, BT, clipboard │
                   └───────────────────┘   └────────────┬────────────┘
                                                        │
                                              ┌─────────▼─────────┐
                                              │  native shim      │
                                              │  (Bluetooth, cgo) │
                                              └───────────────────┘
```

### Choosing a transport

Candidates are the transports enabled locally *and* on a medium the peer is visible on. They rank
by expected throughput — 40 MiB/s for LAN, 40 KiB/s for Bluetooth — with ties broken by name so
the order is always the same. The connection ladder then tries each once, 3 seconds apiece, one
attempt at a time, no retries. If they all fail you get a report naming every transport tried and
why.

While a session runs, a keepalive goes out every 5 seconds. Three consecutive misses mark the
transport unavailable and the session rebinds to the next-best candidate — keeping its identifier,
its keys, and its message sequence state. A transfer resumes from the byte after the last
contiguously acknowledged chunk, re-sliced at the new transport's chunk size. If nothing remains,
the session goes disconnected and holds up to 64 MiB of outbound payload for 10 minutes.

An upgrade back to a faster transport only happens when that transport has been continuously
available for 5 seconds and 30 seconds have passed since the last change, which stops a flapping
link from dragging the session with it.

### Security

| Step | Primitive |
| --- | --- |
| Long-term identity | Ed25519 |
| Pairing code | SHA-256 over both public keys, sorted — 6 digits, valid 120 s |
| Ephemeral exchange | X25519 |
| Key derivation | HKDF-SHA256, salted with both ephemeral keys |
| Payload encryption | ChaCha20-Poly1305, frame header as additional data |
| Trust store integrity | HMAC-SHA256 over canonical entry bytes |

The handshake binds the session keys to both machines' long-term keys and must finish within 5
seconds. Nothing but key exchange messages is processed before it completes. Every payload is
encrypted, including acknowledgements and keepalives — no payload byte appears in a frame in
plaintext. A message that fails its authentication tag is discarded on the first failure with no
retry, the session closes, and the failure is reported.

Session keys are fresh per session and never reused; a rebind reuses the keys it already has rather
than re-keying. The nonce is derived from the handshake role and the sequence number rather than
transmitted, so the only wire overhead is the 16-byte tag.

Logs and error reports carry no secrets by construction: the event log entry type has no field for
message content, and per-message detail is limited to type, sequence number, and payload length.

### Wire format

A fixed 14-byte header, then the payload. Fixed offsets are what make the encoding byte-identical
on every transport.

```
offset  size  field
  0      1    protocolVersion   u8
  1      1    messageType       u8    unknown codes survive parsing
  2      8    sequenceNumber    u64   big-endian
 10      4    payloadLength     u32   big-endian, 0 .. 1,048,576
 14      N    payload                 AEAD ciphertext once a session is up
```

Header fields are validated strictly in order and the first failure is what gets reported, so a
frame from an incompatible version reads as a version problem rather than a size problem. An
unrecognised message type is not an error: the frame is handed up with its raw code and the stream
continues, so a newer peer cannot desynchronise an older one.

### Limits

| Thing | Limit |
| --- | --- |
| Concurrent sessions | 8 |
| Visible peers | 64 |
| Text message | 1 – 65,536 bytes of UTF-8 |
| Clipboard content | 1 MiB, split into 512 KiB parts |
| File size | 1 byte – 64 GiB |
| Chunk size | 64 KiB on LAN, 512 bytes on Bluetooth |
| Frame payload | 1 MiB |
| Trusted peers | at least 32 |

| Timeout | Value |
| --- | --- |
| Presence republish | 5 s |
| Peer expiry | 30 s, swept every 2 s |
| Connect attempt per candidate | 3 s |
| Keepalive / response window | 5 s / 2 s, 3 strikes |
| Rebind attempt | 5 s |
| Key exchange | 5 s |
| Verification code | 120 s |
| Reorder gap hold | 10 s |
| Group delivery outcome | 10 s |
| Chunk acknowledgement | 10 s, 5 resends |
| Transfer offer reply | 60 s |
| Disconnected queue / transfer resume | 10 min |

---

## Project structure

```
cmd/peerbeam/            entrypoint: signal handling and one exit path
internal/
  core/                  pure decision logic — imports no net, no os, no sockets
    clock/               injected time source, so every timeout is testable
    codec/               wire frame encode, incremental decode, message types
    crypto/              HKDF, handshake, seal/open, verification code, fingerprints
    discovery/           announcement validation, the visible peer registry
    session/             session identity, registry, sequencing, reorder, queues, group send
    transport/           Transport interfaces, ranking, connection ladder, switch policy
    text/                size validation, strict UTF-8, inbound disposition
    clipboard/           send validation, part split/join, apply policy, echo suppression
    transfer/            chunk planning, progress, resend tracking, integrity check
    report/              events, failures, status lines, detectors, error-to-report mapping
  platform/              I/O adapters implementing what core declares
    lan/                 TCP transport, UDP multicast beacon, in-process loopback
    bt/                  Bluetooth bridge, transport, helper-process shim, in-memory fabric
    clip/                clipboard via pbcopy / clip.exe / wl-copy / xclip
    share/               macOS share sheet, build-tagged stub elsewhere
    store/               identity key file, trust store, per-OS permissions
  app/                   wiring: node lifecycle, session loops, router, CLI, status renderer
shim/                    per-OS native Bluetooth code (not yet implemented)
.kiro/specs/peerbeam/    requirements, design, and task plan this was built from
```

`internal/core` must never import `net`, `os`, or a socket API. That constraint is what keeps the
protocol testable without a network, and it is worth preserving.

### A session's moving parts

Once admitted, each session runs five goroutines under a child context, so cancelling one session
cannot reach another:

| Loop | Job |
| --- | --- |
| reader | read frames, open payloads, hand them to the inbound channel |
| writer | drain outbound, preferring control traffic over bulk |
| router | act on what arrived: acknowledge, present, apply, reply |
| keepalive | send every 5 s, count strikes |
| metrics | sample goodput once a second |

The writer polls the control channel with a non-blocking select before waiting on either channel.
Go's `select` picks uniformly among ready cases, so a plain three-way select would give a saturated
bulk channel an even chance and a text message would queue behind a file transfer's chunks.

State is split deliberately. Things that survive a transport change — session id, keys, sequence
state — live on the session. Things that belong to the connection — keepalive strikes, throughput
samples — live on the binding and are discarded on rebind, because ten below-target samples on a
dying Wi-Fi link say nothing about the Bluetooth link that replaced it.

---

## Files on disk

Everything lives in `~/.peerbeam` (override with `--state-dir`):

| File | Contents |
| --- | --- |
| `identity.key` | Ed25519 private key, PEM. Created on first run, owner-only. |
| `trusted.json` | Trusted peers plus an HMAC-SHA256 integrity tag. |

`identity.key` is `0600` on macOS and Linux, and carries an ACL granting only the current user on
Windows, where mode bits mean nothing. The permissions are verified on every start, not only at
creation — a key loosened by a careless `chmod` or a restore that dropped modes is caught, and the
node refuses sessions until it is fixed.

`trusted.json` is tagged with a key derived from the identity, so a stray edit or a bad restore is
detected and every session request is refused rather than trusting entries that cannot be verified.
The tag covers canonical field bytes rather than the file bytes, so reformatting the JSON is not
mistaken for tampering. Writes go through a temporary file and a rename, so a crash mid-write
cannot lose your paired keys.

---

## Development

```sh
make build       # compile for this machine, leaving ./peerbeam
make install     # build onto your PATH, so a bare `peerbeam` works
make test        # run every test
make test-race   # run every test under the race detector
make vet         # go vet for the host and all five release targets
make fmt         # check gofmt cleanliness
make check       # fmt + vet + test-race
make release     # cross-compile all targets, enforce the size ceiling
make smoke       # start a fresh binary, check readiness and key permissions
make clean
make help
```

### Testing approach

Roughly 15,000 lines of production code and 14,000 of tests. The design names 41 correctness
properties and all 41 are covered with [rapid](https://pgregory.net/rapid) property tests, each
running at least 100 generated cases, alongside fixed-input tests for the boundaries random
generation rarely hits.

The properties are the point. A few examples of what they actually catch:

- **Stream framing under arbitrary segmentation** — the same byte stream cut at any set of points,
  including mid-header, produces the same frames in the same order.
- **Sealed payloads reject every tamper** — flipping any single bit of the header or the ciphertext
  makes decryption fail.
- **The switch rule table** — every combination of pin, availability, and timing yields exactly one
  decision, asserted clause by clause rather than against a reimplementation.
- **Chunk plans cover a file exactly once** — across a chunk-size change partway through, every
  byte is written exactly once and reassembles to a matching digest.
- **Logs never contain secrets** — no rendered event or failure report contains payload, clipboard,
  file, or key bytes.

Where a requirement's bound is timing-based, a `Clock` is injected and tests advance it by hand
rather than sleeping, so the whole suite runs in seconds.

Timing and hardware measurements that need a reference LAN or two Bluetooth radios — the throughput
and latency targets — are documented manual procedures per release rather than automated tests.

### Contributing

Two rules are worth stating because the codebase leans on them:

1. **`internal/core` imports no I/O.** If a decision needs the network or the filesystem, the
   decision belongs in core and the I/O belongs behind an interface in `internal/platform`.
2. **Every user-visible failure goes through `report.Describe`.** It is the single place that
   guarantees a failure names the operation, the peer, the reason, and a remediation step.

Run `make check` before opening a pull request.

---

## Out of scope

Peerbeam covers shared-network and Bluetooth paths between machines you own. Deliberately not
included: relay or rendezvous servers for peers separated by the internet, NAT traversal,
programmatic AirDrop control, clipboard formats other than plain text, a graphical interface, group
chat semantics, and mobile platforms.

---

## License

MIT. See [LICENSE](LICENSE).
