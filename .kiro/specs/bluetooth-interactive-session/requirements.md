# Requirements Document

## Introduction

This feature makes Peerbeam usable as an application rather than a library with a command surface over it. It has two halves, and they are coupled.

The first half is **connection over a medium that is not a shared IP network**. The parent spec always named BT_Transport as a first-class transport, and `internal/platform/bt` implements the whole Go side of it against a `BluetoothBridge` interface, with property tests. What never existed is the native code behind that interface: `shim/macos`, `shim/windows`, and `shim/linux` contained only README files, so `BluetoothBridge.Available()` was false on every real host and every Peer_Node ran LAN-only. A user with two machines on different networks therefore had no path between them at all, which is the case this feature exists to serve.

The second half is an **interactive session**. Today every command constructs a Peer_Node, queries it, and exits. Nothing in the production CLI calls `PeerNode.Start`, so no listener accepts inbound connections, no presence is published, no presence is received, and the visible Peer list is empty by construction. `peerbeam peers` cannot show a Peer on any network for any reason. Because each invocation is a fresh process holding all state in memory, nothing carries between commands except `identity.key` and `trusted.json`. A live conversation cannot be assembled out of one-shot commands: it needs one process that stays up, holds the Session open, prints Messages as they arrive, and reads what the user types.

The two halves are coupled because the interactive flow is what makes the missing pieces unavoidable. Selecting a Peer from a list requires discovery to actually run. Reaching "connection established" with a Peer met for the first time requires the pairing exchange, which is specified in the parent design but has no wire implementation: `PairingService.BeginPairing` takes the peer's public key as a parameter, and nothing in the codebase ever obtains one from a remote machine.

Scope is deliberately narrow. This feature delivers Bluetooth on macOS and an interactive text messaging flow. It does not deliver the Windows or Linux shims, the Transfer sender loop, peer-to-peer Wi-Fi, or any relay for Peers separated by the internet.

### What already exists

Stated plainly, because the work here is smaller than it looks and the existing pieces constrain the design:

- `bt.BluetoothBridge`, `bt.BtTransport`, `bt.ShimBluetoothBridge` (the helper-process client), `bt.InMemoryBluetoothBridge` (the test double), and the shim frame protocol are implemented and tested.
- `lan.Beacon` implements presence publication and reception over UDP multicast, with tests. It is not referenced anywhere in `internal/app`.
- `trust.PairingService` implements fingerprints, the 6-digit verification code, both confirmation sides, and the trust store, with tests.
- `PeerNode.Start` and `PeerNode.Stop` exist and manage accept loops, the expiry sweep, and a single join point. Nothing in production calls them.
- `PeerRegistry` was made safe for concurrent use in preparation for this feature.

## Glossary

Terms from the parent Peerbeam spec carry over unchanged. These are additional.

- **BT_Shim**: A per-operating-system native executable that implements Bluetooth radio access on behalf of a Peer_Node. It is a separate process, not linked into the Peer_Node binary, and communicates over its standard input and standard output.
- **Shim_Frame**: The unit of communication between a Peer_Node and its BT_Shim: a 9-byte header carrying a kind, a stream identifier, and a payload length, followed by the payload.
- **Shim_Stream**: One bidirectional byte stream between two Peer_Nodes carried over a BT_Shim, identified by a stream identifier that is unique within one shim process.
- **L2CAP_Channel**: A Bluetooth Low Energy connection-oriented channel, which presents as a bidirectional byte stream and is the mechanism a BT_Shim uses to carry a Shim_Stream.
- **PSM**: The Protocol/Service Multiplexer value identifying a published L2CAP_Channel on one machine. It is assigned by the operating system when the channel is published and is therefore not a constant.
- **Announcement_Record**: The encoded Announcement bytes as defined by the parent spec, carried unchanged by every medium. A BT_Shim treats it as opaque.
- **Presence_Source**: A component that publishes the local Peer_Node's presence on one medium and feeds Announcements received on that medium into the visible Peer list. LAN_Presence wraps the multicast beacon; BT_Presence wraps BT_Transport advertising and scanning.
- **Bluetooth_Authorization**: The operating system's permission grant allowing a process to use the Bluetooth radio. On macOS this is granted to the process that launched the Peer_Node, not to the Peer_Node or its BT_Shim.
- **Interactive_Session**: A single long-lived Peer_Node process that presents the visible Peer list, takes a selection, establishes a Session, and then exchanges text Messages until the user leaves.
- **Peer_Picker**: The stage of an Interactive_Session that displays the visible Peer list and accepts a selection, a rescan, or a quit.
- **Chat_View**: The stage of an Interactive_Session that displays received Messages and accepts lines of text to send.
- **Pairing_Exchange**: The Message exchange that carries each Peer_Node's long-term public key and display name to the other, so that a Pairing_Service on each side can derive a verification code and, on mutual confirmation, record a Trusted_Peer.
- **first contact**: A connection attempt to a Peer that is not yet a Trusted_Peer, and for which no long-term public key is held locally.

## Requirements

### Requirement 1: A Working Bluetooth Transport on macOS

**User Story:** As a user whose two machines are on different networks, I want them to reach each other over Bluetooth, so that I can move text between them without a shared network or the internet.

#### Acceptance Criteria

1. THE project SHALL provide a BT_Shim for macOS, built from source in the repository by a single documented command, producing one executable at the path `bt.ShimPath` resolves to.
2. WHEN the BT_Shim executable is absent, THE Peer_Node SHALL reach ready state, report BT_Transport as unavailable naming the missing shim, and continue with the remaining transports, as the parent spec's Requirement 12.3 already requires.
3. WHEN the BT_Shim is present and the host Bluetooth radio is usable, THE Peer_Node SHALL treat BT_Transport as a candidate Transport for any Peer visible on the Bluetooth medium.
4. THE BT_Shim SHALL communicate with the Peer_Node exclusively in Shim_Frames over its standard input and standard output, and SHALL write no other bytes to standard output.
5. THE BT_Shim SHALL write diagnostic output to standard error only, so that a native failure is visible without corrupting the Shim_Frame stream.
6. WHEN the Peer_Node closes the BT_Shim's standard input, THE BT_Shim SHALL exit.
7. WHEN the BT_Shim exits, fails, or emits a Shim_Frame whose declared payload length exceeds the protocol maximum, THE Peer_Node SHALL fail every open Shim_Stream with an error rather than blocking, so that affected Sessions can rebind to another candidate Transport.
8. THE BT_Shim SHALL require no operating-system Bluetooth pairing between the two machines, since Session payloads are already encrypted by the Session layer.

### Requirement 2: Diagnosable Bluetooth Authorization

**User Story:** As a user setting this up for the first time, I want to be told exactly why Bluetooth is not working, so that I am not left guessing at a silent failure.

#### Acceptance Criteria

1. WHEN the operating system denies Bluetooth_Authorization, THE BT_Shim SHALL report Bluetooth as unavailable to the Peer_Node rather than exiting silently or crashing.
2. WHEN Bluetooth_Authorization is denied, THE Peer_Node SHALL report BT_Transport as unavailable with a reason naming authorization as the cause, and with a remediation step naming the grant the user must make.
3. THE BT_Shim build SHALL embed the platform metadata required for an authorization prompt to be possible, and SHALL fail the build if that metadata is absent from the produced executable.
4. THE BT_Shim documentation SHALL state that on macOS the authorization applies to the process that launched the Peer_Node rather than to the Peer_Node or the BT_Shim.
5. WHEN the Bluetooth radio is powered off, THE Peer_Node SHALL report BT_Transport as unavailable with a reason distinguishing a powered-off radio from a denied authorization and from an absent shim.

### Requirement 3: Presence Published on Every Available Medium

**User Story:** As a user, I want each of my machines to announce itself on whatever media it has, so that the other machine can find it without configuration.

#### Acceptance Criteria

1. WHEN a Peer_Node starts, THE Peer_Node SHALL start one Presence_Source for each medium whose Transport is available, and SHALL record a startup report entry for each medium it could not start.
2. WHILE a Peer_Node is running with an available BT_Transport, THE BT_Presence source SHALL publish the local Announcement_Record over Bluetooth and SHALL republish it at least every 10 seconds, satisfying the parent spec's Requirement 1.9 on the Bluetooth medium.
3. WHILE a Peer_Node is running with an available LAN_Transport, THE LAN_Presence source SHALL publish and receive Announcements over UDP multicast as the parent spec's Requirement 1.1 and 1.3 already specify.
4. WHERE an Announcement_Record is larger than one Bluetooth advertisement can carry, THE BT_Presence source SHALL advertise only a fixed service identifier and SHALL make the complete Announcement_Record retrievable by a Peer that has seen that advertisement.
5. WHEN the listening port changes after a Presence_Source has started, THE Peer_Node SHALL publish the port actually bound rather than the requested one.
6. WHEN a Presence_Source fails after starting, THE Peer_Node SHALL report the failure naming the medium, and SHALL leave the other Presence_Sources running.

### Requirement 4: Peers Discovered Over Bluetooth

**User Story:** As a user with two machines and no shared network, I want each to appear in the other's Peer list, so that I can pick one and connect.

#### Acceptance Criteria

1. WHEN a Peer publishes its presence over Bluetooth within radio range, THE Peer_Node SHALL add that Peer to the visible Peer list within 15 seconds, as the parent spec's Requirement 1.4 allows.
2. THE Peer_Node SHALL record the Bluetooth medium and a device identifier for each Peer discovered over Bluetooth, and that device identifier SHALL be sufficient for a later connection attempt to that Peer without rescanning.
3. WHEN an Announcement_Record received over Bluetooth is malformed, THE Peer_Node SHALL discard it, leave the visible Peer list unchanged, and record a malformed-announcement event, identically to the LAN path, satisfying the parent spec's Requirement 1.11.
4. WHEN an Announcement_Record received over Bluetooth carries the local Peer_Node's own fingerprint, THE Peer_Node SHALL ignore it.
5. WHEN the same Peer is discovered on both the Bluetooth and LAN media, THE Peer_Node SHALL hold one visible Peer list entry listing both media, satisfying the parent spec's Requirement 1.8.
6. WHILE two Presence_Sources are running, THE visible Peer list SHALL remain internally consistent under concurrent observation, expiry, and reads.

### Requirement 5: A Live Node Behind the Command Line

**User Story:** As a user, I want the application to actually be running while I use it, so that it can receive Messages and hold connections open.

#### Acceptance Criteria

1. WHEN the user invokes a command that requires discovery, a Session, or inbound connections, THE application SHALL start the Peer_Node's background loops before serving that command.
2. WHEN a started Peer_Node is no longer needed, THE application SHALL stop it and SHALL wait for every goroutine it started, so that the process exits with no loop still running.
3. WHEN the user interrupts the process, THE application SHALL stop the Peer_Node through the same single path as a normal exit, and SHALL not leave a BT_Shim process running.
4. WHERE a command needs only local state and no medium, THE application MAY serve that command without starting the Peer_Node, and SHALL document which commands those are.
5. WHEN a command needs discovery results, THE application SHALL allow discovery a bounded interval to produce them before rendering, and SHALL state that it is waiting rather than rendering an empty list immediately.

### Requirement 6: Selecting a Peer Interactively

**User Story:** As a user, I want to start the application and see who is around, so that I can pick a machine without typing a 64-character fingerprint.

#### Acceptance Criteria

1. WHEN the user starts the Interactive_Session, THE Peer_Picker SHALL display the visible Peer list with, for each Peer, a short selection index, the display name, an abbreviated fingerprint, and the media it was seen on.
2. WHILE the Peer_Picker is displayed, THE Peer_Picker SHALL indicate which Peers are already Trusted_Peers and which would require pairing on selection.
3. WHILE the Peer_Picker is displayed and no Peer is yet visible, THE Peer_Picker SHALL say that it is still discovering rather than presenting an empty list as a final answer.
4. WHEN the user enters a selection index that identifies a visible Peer, THE Interactive_Session SHALL proceed to establish a Session with that Peer.
5. WHEN the user enters an input that is not a valid selection, THE Peer_Picker SHALL say so and SHALL redisplay the list without exiting.
6. THE Peer_Picker SHALL offer an explicit way to refresh the list and an explicit way to leave the application.
7. WHEN a Peer appears or expires while the Peer_Picker is displayed, THE Peer_Picker SHALL reflect that on its next display, and selection indices SHALL identify the Peer they were shown against rather than a list position that has since shifted.

### Requirement 7: Establishing the Connection With Visible Progress

**User Story:** As a user who has just picked a machine, I want to be told what is happening and when I can start typing, so that I am not typing into a connection that does not exist.

#### Acceptance Criteria

1. WHEN the user selects a Peer, THE Interactive_Session SHALL report which Transport it is attempting, in ranked order, as it attempts each.
2. WHEN a Session is established, THE Interactive_Session SHALL state that the connection is established, name the Peer, and name the active Transport, before accepting any Message input.
3. WHEN every candidate Transport fails, THE Interactive_Session SHALL report the failure naming each Transport attempted and why, and SHALL return to the Peer_Picker rather than exiting.
4. WHEN the selected Peer is not a Trusted_Peer, THE Interactive_Session SHALL carry out the Pairing_Exchange before establishing the Session, and SHALL not present a Chat_View for an unpaired Peer.
5. WHEN the active Transport changes while a Chat_View is open, THE Interactive_Session SHALL say so, naming the new Transport, and SHALL keep the Chat_View open.
6. WHEN the Session enters the disconnected state while a Chat_View is open, THE Interactive_Session SHALL say so and SHALL indicate that Messages the user sends are being queued.

### Requirement 8: Exchanging Messages Interactively

**User Story:** As a user, I want to type a message and see the reply, so that the two machines hold a conversation.

#### Acceptance Criteria

1. WHILE a Chat_View is open, THE Interactive_Session SHALL send each line the user submits as a text Message to the connected Peer.
2. WHEN a text Message arrives on the Session, THE Chat_View SHALL display it attributed to the sending Peer's display name, without the user having to issue a command to fetch it.
3. WHEN a Message arrives while the user has partially typed a line, THE Chat_View SHALL not discard or corrupt the partially typed line.
4. WHEN a line the user submits is empty, THE Chat_View SHALL send nothing.
5. WHEN a line the user submits exceeds the text Message size limit of the parent spec's Requirement 5, THE Chat_View SHALL refuse it, say why, and keep the Chat_View open.
6. WHEN sending fails, THE Chat_View SHALL report the failure against that Message and SHALL keep the Chat_View open.
7. THE Chat_View SHALL offer an explicit way to leave the conversation, which SHALL close the Session and return to the Peer_Picker.
8. WHEN the Peer closes the Session, THE Chat_View SHALL say so and SHALL return to the Peer_Picker.
9. THE Chat_View SHALL distinguish Messages sent by the local user from Messages received from the Peer.

### Requirement 9: Pairing on First Contact

**User Story:** As a user connecting two machines for the first time, I want to confirm a code on both, so that I know I am connected to my own machine and not to someone else on the same network.

#### Acceptance Criteria

1. WHEN a Peer_Node attempts a connection to a Peer at first contact, THE Pairing_Exchange SHALL carry each side's long-term public key and display name to the other over the connection.
2. WHEN a Peer_Node receives a peer's long-term public key through the Pairing_Exchange, THE Pairing_Service SHALL derive the verification code from both public keys locally, and the code SHALL NOT be transmitted.
3. WHEN both Peer_Nodes have exchanged public keys, THE Peer_Node SHALL display the derived verification code to its user and SHALL wait for that user to confirm or reject it.
4. WHEN both users confirm, THE Peer_Node SHALL record the Peer as a Trusted_Peer and SHALL proceed to establish the Session.
5. WHEN either user rejects, THE Peer_Node SHALL record no trust, SHALL close the connection, and SHALL report that pairing was rejected.
6. WHEN the verification code's validity interval elapses before both users decide, THE Peer_Node SHALL abandon the Pairing_Exchange, record no trust, and report the expiry.
7. WHEN the Pairing_Exchange carries a public key that does not match a key already held for that fingerprint, THE Peer_Node SHALL refuse the connection and SHALL report a key mismatch distinctly from an untrusted peer, preserving the existing behaviour tested by the parent spec.
8. THE Peer_Node SHALL NOT process any Message other than the Pairing_Exchange and the key exchange before trust is established.
9. WHEN a Peer_Node receives an inbound Pairing_Exchange, THE Peer_Node SHALL prompt its own user rather than accepting trust automatically.

### Requirement 10: Reporting Inside the Interactive Session

**User Story:** As a user, I want failures explained in place, so that I do not have to leave the conversation to find out what went wrong.

#### Acceptance Criteria

1. THE Interactive_Session SHALL render every user-visible failure through the parent spec's single failure description mapping, so that each names the operation, the Peer, the reason, and a remediation step.
2. THE Interactive_Session SHALL NOT display Message payloads, clipboard content, file content, or key material in any failure report or event line, preserving the parent spec's Requirement 10.6 and 13.5.
3. WHEN a startup report entry exists for an unavailable medium, THE Interactive_Session SHALL show it once at startup rather than repeating it per Peer or per Message.
4. WHERE the Interactive_Session displays status, it SHALL use the parent spec's all-or-nothing status rule, showing a pending state rather than a partial measurement.

### Requirement 11: Platform Posture and Non-Goals

**User Story:** As a user on Windows or Linux, I want to know what this does and does not give me, so that my expectations match the software.

#### Acceptance Criteria

1. THE feature SHALL deliver a BT_Shim for macOS only, and SHALL report BT_Transport as unavailable with a reason naming the absent shim on every other operating system.
2. THE Peer_Node SHALL continue to build and pass its tests for every release target of the parent spec's Requirement 12.2, whether or not a BT_Shim exists for that target.
3. THE feature SHALL NOT introduce a relay, rendezvous, or NAT traversal mechanism, so two Peers with neither a shared network nor Bluetooth range remain unable to connect.
4. THE feature SHALL NOT use AirDrop as a Transport, consistent with the parent spec's exclusion of it.
5. THE feature SHALL NOT deliver the Transfer sender loop; file commands remain as they are.
6. WHERE the interactive flow needs a capability that is not implemented, THE application SHALL say so at the point of use rather than appearing to succeed.
