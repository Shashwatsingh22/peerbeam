# Requirements Document

## Introduction

Peerbeam is a peer-to-peer application that moves short text messages, clipboard contents, and files between two or more personal computers. Peers may sit on the same local network, on different networks, or on no network at all, so the application carries traffic over multiple interchangeable transports and selects the fastest one that is currently reachable.

The first deliverable is a minimal messaging application: one instance can hold live sessions with several macOS peers simultaneously over the local network, and can fall back to Bluetooth when a peer is on a different network or runs a different operating system. Clipboard sharing and file transfer are built on top of that messaging layer.

Apple AirDrop is deliberately excluded as a programmable transport. AirDrop exposes no public API for third-party applications, so the application can only hand a file to the operating system share sheet and let the user complete an AirDrop transfer manually. This is treated as a user-driven escape hatch, not as a transport the application controls.

## Glossary

- **Peer_Node**: A single running instance of the application on one machine. Every Peer_Node acts as both client and server.
- **Peer**: A remote Peer_Node that is visible to, or connected with, the local Peer_Node.
- **Transport**: A concrete mechanism for carrying bytes between two Peer_Nodes. The defined transports are LAN_Transport and BT_Transport.
- **LAN_Transport**: A transport that carries traffic over IP between two Peer_Nodes that can reach each other directly on a shared network.
- **BT_Transport**: A transport that carries traffic over a Bluetooth link between two Peer_Nodes, requiring no IP network.
- **candidate Transport**: A Transport that is enabled on the local Peer_Node and on whose medium the Peer is present in the visible Peer list. Only candidate Transports are ranked, attempted, or rebound to for a Session with that Peer.
- **Transport pin**: A user setting that binds one Session to one named Transport, suppressing rank-based Transport switching for that Session.
- **Discovery_Service**: The component that finds Peers and publishes the local Peer_Node's presence on each available medium.
- **Transport_Manager**: The component that opens, ranks, monitors, and switches Transports for a Session.
- **Session**: An authenticated, encrypted, logical channel between the local Peer_Node and one Peer, bound at any moment to exactly one active Transport.
- **disconnected state**: The state of a Session that has no available candidate Transport, in which the Session retains its identifier, negotiated keys, Message sequence state, and queued outbound Messages while awaiting reconnection.
- **Message**: The unit of application data exchanged inside a Session. Every Message has a type, a monotonically increasing sequence number, and a payload.
- **Message_Codec**: The component that serializes a Message to wire bytes and parses wire bytes back into a Message.
- **Wire_Frame**: The length-prefixed byte sequence produced by Message_Codec for one Message.
- **Pairing_Service**: The component that establishes mutual trust between two Peer_Nodes and stores the resulting long-term keys.
- **Trusted_Peer**: A Peer whose public key is present in the local Peer_Node's trust store as the result of a completed pairing.
- **Clipboard_Service**: The component that reads the local system clipboard and applies received clipboard contents to it.
- **pending clipboard entry**: Clipboard content received on a Session and held unapplied by the Clipboard_Service while it awaits a user decision to confirm or decline, limited to one entry per Session.
- **Transfer_Service**: The component that sends and receives files as ordered sequences of chunks.
- **Chunk**: A fixed-size slice of a file payload carried by a single Message.
- **Transfer**: One file-sending operation, identified by a transfer identifier, covering all Chunks of one file.
- **Goodput**: Application-level payload bytes delivered per second, excluding protocol framing and encryption overhead.
- **ready state**: The state a launched Peer_Node reaches once it has loaded its key store and trust store, enumerated its available media, and can accept user commands.
- **Reference_LAN**: A test environment of two machines on the same Gigabit Ethernet or 802.11ac wireless network with a measured round-trip time of 5 ms or less.

## Requirements

### Requirement 1: Peer Discovery Without Manual Addressing

**User Story:** As a user with two machines, I want each machine to find the other by itself, so that I never have to look up or type an IP address.

#### Acceptance Criteria

1. WHEN a Peer_Node starts, THE Discovery_Service SHALL publish, within 2 seconds and on each medium the host reports as available, the local Peer_Node's display name of at most 64 UTF-8 characters, public key fingerprint, protocol version, and listening port.
2. WHILE a Peer_Node is running, THE Discovery_Service SHALL maintain a list of up to 64 visible Peers, each entry carrying the Peer's display name, public key fingerprint, declared protocol version, whether that declared protocol version is supported by the local Peer_Node, and each medium on which that Peer was observed.
3. WHEN a Peer becomes visible on a shared IP network, THE Discovery_Service SHALL add that Peer to the visible Peer list within 5 seconds of the Peer publishing its presence on that network.
4. WHEN a Peer becomes visible over Bluetooth, THE Discovery_Service SHALL add that Peer to the visible Peer list within 15 seconds of the Peer starting to advertise.
5. WHEN no presence announcement from a visible Peer is observed on any medium for 30 seconds, THE Discovery_Service SHALL remove that Peer from the visible Peer list within 5 seconds.
6. WHEN the user supplies a host address and a port in the range 1 to 65535 for a Peer that is not present in the visible Peer list, THE Discovery_Service SHALL add that Peer to the visible Peer list within 2 seconds, annotated as manually supplied, without waiting for automatic discovery.
7. IF the user supplies a host address and port for a Peer that is already present in the visible Peer list, THEN THE Discovery_Service SHALL update the existing entry with the supplied address and port and keep a single entry for that Peer.
8. IF two visible Peers report the same public key fingerprint, THEN THE Discovery_Service SHALL keep a single entry for that fingerprint that lists every medium on which it was observed and SHALL retain the most recently observed address and port for each of those media.
9. WHILE a Peer_Node is running, THE Discovery_Service SHALL republish the local Peer_Node's presence on each available medium at intervals of 10 seconds or shorter.
10. IF the user supplies a host address that cannot be resolved or a port outside the range 1 to 65535, THEN THE Discovery_Service SHALL reject the supplied entry, leave the visible Peer list unchanged, and report an error indicating whether the address or the port was rejected.
11. IF a received presence announcement omits the display name, public key fingerprint, protocol version, or listening port, or declares a port outside the range 1 to 65535, or carries a display name longer than 64 UTF-8 characters, THEN THE Discovery_Service SHALL discard the announcement, leave the visible Peer list unchanged, and record a malformed announcement event.

### Requirement 2: Speed-First Transport Selection

**User Story:** As a user sending a large file, I want the application to pick the fastest available path by itself, so that I get the best speed without choosing a transport.

#### Acceptance Criteria

1. THE Transport_Manager SHALL treat a Transport as a candidate Transport for a Peer when that Transport is enabled on the local Peer_Node and the Peer is present in the visible Peer list on that Transport's medium, and SHALL rank candidate Transports in descending order of expected Goodput using 40 mebibytes per second for LAN_Transport and 40 kibibytes per second for BT_Transport, so that LAN_Transport ranks above BT_Transport.
2. WHEN two candidate Transports for a Peer carry the same expected Goodput, THE Transport_Manager SHALL order them by ascending Transport name so that repeated ranking of the same candidate set yields the same order.
3. WHEN a Session is requested for a Peer, THE Transport_Manager SHALL attempt the highest ranked candidate Transport first and SHALL hold at most one connection attempt open for that Session at a time.
4. IF a candidate Transport does not complete a connection within 3 seconds of the attempt starting, THEN THE Transport_Manager SHALL abandon that attempt and attempt the next ranked candidate Transport once, without retrying any already attempted Transport.
5. IF every candidate Transport fails to connect, THEN THE Transport_Manager SHALL create no Session and SHALL report, within 1 second of the last attempt ending, a connection failure that names each attempted Transport in attempt order together with the failure reason for that Transport.
6. IF a Session is requested for a Peer that has no candidate Transport, THEN THE Transport_Manager SHALL create no Session and SHALL report a failure indicating that no Transport is available for that Peer.
7. WHILE a Session is active, THE Transport_Manager SHALL sample and record the measured Goodput and the measured round-trip time of the active Transport at intervals of 1 second or shorter, and SHALL retain the most recent sample of each value for the duration of the Session.
8. WHILE a Session is active and no Transport pin applies to it, WHEN a candidate Transport ranked above the active Transport has been continuously available for 5 seconds and at least 30 seconds have elapsed since the last Transport change on that Session, THE Transport_Manager SHALL switch the Session to that Transport after the in-flight Message completes and no later than 30 seconds after the higher ranked Transport qualified.
9. IF a switch to a higher ranked Transport does not complete within 3 seconds, THEN THE Transport_Manager SHALL keep the Session on its current active Transport, retain the Session identifier and Message sequence state, and report a switch failure that names both Transports and the failure reason.
10. WHERE the user pins a Session to a named Transport, THE Transport_Manager SHALL use only that Transport for the Session and SHALL perform no rank-based Transport switching for that Session.
11. WHERE the user pins a Session to a named Transport, IF that Transport becomes unavailable, THEN THE Transport_Manager SHALL place the Session in a disconnected state without switching Transports and report a failure that names the pinned Transport and the reason it became unavailable.

### Requirement 3: Transport Failover Without Losing Work

**User Story:** As a user who walks out of Wi-Fi range mid-transfer, I want the session to survive on Bluetooth, so that my transfer continues instead of failing.

#### Acceptance Criteria

1. WHILE a Session is active, THE Transport_Manager SHALL send a keepalive Message every 5 seconds on the active Transport.
2. IF three consecutive keepalive Messages each receive no response within 2 seconds of being sent, THEN THE Transport_Manager SHALL mark the active Transport as unavailable.
3. WHEN the active Transport of a Session is marked unavailable, THE Transport_Manager SHALL rebind the Session to the highest ranked remaining candidate Transport within 5 seconds of the mark.
4. WHEN a Session is rebound to another Transport, THE Session SHALL retain its identifier, its negotiated keys, and its Message sequence state.
5. WHEN a Session is rebound to another Transport during a Transfer, THE Transfer_Service SHALL resume that Transfer within 5 seconds of the rebind completing, starting from the byte offset that follows the last contiguously acknowledged Chunk and slicing the remaining content into Chunks at the Chunk size of the new Transport.
6. IF no candidate Transport remains available for a Session, THEN THE Peer_Node SHALL place the Session in a disconnected state and retain up to 64 mebibytes of queued outbound Message payload for 10 minutes.
7. WHEN a Session in a disconnected state regains a candidate Transport within 10 minutes, THE Peer_Node SHALL reconnect the Session and send the retained queued outbound Messages in ascending sequence number order within 5 seconds of the reconnection completing.
8. IF a rebind attempt to a candidate Transport does not complete within 5 seconds, THEN THE Transport_Manager SHALL mark that candidate Transport as unavailable and attempt the next ranked candidate Transport.
9. IF a Session remains in a disconnected state for 10 minutes, THEN THE Peer_Node SHALL discard its retained queued outbound Messages and report a delivery failure that names each discarded Message sequence number.
10. IF an outbound Message is submitted on a Session in a disconnected state whose retained queue already holds 64 mebibytes of payload, THEN THE Peer_Node SHALL reject that Message, leave the retained queue unchanged, and report an error indicating the retention limit is reached.

### Requirement 4: Concurrent Multi-Peer Sessions

**User Story:** As a user with several machines on my desk, I want one instance connected to all of them at once, so that I can push text or files to any of them without reconnecting.

#### Acceptance Criteria

1. THE Peer_Node SHALL maintain up to 8 concurrent Sessions with distinct Peers, each Session holding its own Session identifier, negotiated keys, Message sequence state, and active Transport.
2. WHILE more than one Session is active, THE Peer_Node SHALL hold a separate inbound and outbound Message queue for each Session and SHALL send and deliver Messages on one Session without waiting for a Message, a Transfer, or a Transport change on any other Session to complete.
3. IF one Session enters a disconnected state, THEN THE Peer_Node SHALL keep every other active Session active and leave each of those Sessions' Session identifier, negotiated keys, Message sequence state, and active Transport unchanged.
4. WHEN the user sends a Message to a selected group of up to 8 Peers, THE Peer_Node SHALL send that Message on the Session of each selected Peer whose Session is active, using that Session's own next sequence number.
5. IF no delivery acknowledgement is received within 10 seconds from part of a selected group of Peers, THEN THE Peer_Node SHALL continue delivery to the remaining selected Peers of that group and report an outcome of not delivered for each unacknowledged Peer that names the Peer and the failure reason.
6. WHILE a Transfer is running on one Session, THE Peer_Node SHALL accept text Messages on every other active Session and deliver each accepted text Message with a 95th percentile end-to-end latency of 100 milliseconds or less on a Reference_LAN.
7. WHEN the user sends a Message to a selected group of Peers, THE Peer_Node SHALL report one delivery outcome per selected Peer within 10 seconds of the send, each outcome naming the Peer and stating delivered or not delivered.
8. IF the user sends a Message to a selected group that includes a Peer whose Session is not active, THEN THE Peer_Node SHALL report an outcome of not delivered for that Peer, retain the Message in that Session's queued outbound Messages, and complete delivery to the selected Peers whose Sessions are active.
9. IF a Session is requested while 8 Sessions are active, THEN THE Peer_Node SHALL reject the requested Session, report a concurrent Session limit error that names the limit of 8, and keep the 8 active Sessions in their current state.

### Requirement 5: Text Messaging

**User Story:** As a user, I want to send a line of text to another machine, so that I can move a link, a command, or a note across machines quickly.

#### Acceptance Criteria

1. WHEN the user submits text of 1 to 65,536 bytes of UTF-8 encoded content on an active Session, THE Peer_Node SHALL assign the text the next sequence number of that Session and send it to the Peer as a single text Message.
2. THE Peer_Node SHALL accept text Messages carrying a payload of 1 to 65,536 bytes (64 kibibytes) of UTF-8 encoded content.
3. WHEN a text Message is received and the Message content, the sending Peer's display name, and the receipt timestamp are all available, THE Peer_Node SHALL display all three together within 1 second of receipt.
4. IF a text Message is received and any of the Message content, the sending Peer's display name, or the receipt timestamp is unavailable, THEN THE Peer_Node SHALL withhold the Message from display, record an incomplete Message event that names the Message sequence number and each unavailable item, and keep the Session active.
5. WHEN a text Message is received, THE Peer_Node SHALL return a delivery acknowledgement that carries the Message sequence number within 1 second of receipt.
6. IF a text Message payload is not valid UTF-8, THEN THE Peer_Node SHALL return a delivery acknowledgement that carries the Message sequence number, withhold the Message content from display, and return an error Message that names the offending sequence number and indicates invalid UTF-8 encoding.
7. WHILE a Session is active, THE Peer_Node SHALL present received text Messages of that Session in ascending sequence number order, withholding a Message that follows a missing sequence number for up to 10 seconds while awaiting the missing Message and presenting it once 10 seconds have elapsed without the missing Message arriving.
8. IF the user submits text that is empty or exceeds 65,536 bytes of UTF-8 encoded content on an active Session, THEN THE Peer_Node SHALL send no text Message, retain the submitted text unchanged, and report an error indicating the permitted content size range.
9. IF a received text Message carries a payload larger than 65,536 bytes, THEN THE Peer_Node SHALL withhold the Message content from display, return an error Message that names the offending sequence number and the maximum accepted payload size, and keep the Session active.
10. IF a text Message is received with a sequence number already received on the same Session, THEN THE Peer_Node SHALL discard the duplicate Message, return a delivery acknowledgement that carries that sequence number, and display the content once only.

### Requirement 6: Clipboard Sharing

**User Story:** As a user who just copied something on one machine, I want it available to paste on another machine, so that I do not retype it.

#### Acceptance Criteria

1. WHEN the user triggers a clipboard send on an active Session and the local clipboard holds text content of 1 mebibyte or less of UTF-8 encoded content, THE Clipboard_Service SHALL read that text content and send it to the Peer as a single clipboard Message.
2. WHERE automatic clipboard apply is enabled, WHEN a clipboard Message is accepted on a Session, THE Clipboard_Service SHALL replace the entire local clipboard text content with the received content within 1 second of receipt.
3. WHERE automatic clipboard apply is disabled, WHEN a clipboard Message is accepted on a Session, THE Clipboard_Service SHALL retain the received content as a pending clipboard entry for 10 minutes, keep at most 1 pending entry per Session by discarding any earlier pending entry of that Session, and prompt the user to confirm or decline the entry with the sending Peer's display name and the receipt timestamp.
4. WHERE automatic clipboard apply is disabled, WHEN the user confirms a pending clipboard entry within its 10 minute retention period, THE Clipboard_Service SHALL replace the entire local clipboard text content with the retained content and discard the pending entry.
5. WHERE continuous clipboard sync is enabled for a Session, WHILE that Session is active, WHEN the local clipboard text content changes to content that the Clipboard_Service did not apply from a clipboard Message received on that Session, THE Clipboard_Service SHALL send the changed content as a clipboard Message within 1 second of the change.
6. IF a received clipboard Message carries content identical to the content that the Clipboard_Service most recently applied or most recently sent on the same Session, THEN THE Clipboard_Service SHALL discard the Message, leave the local clipboard unchanged, and raise no user prompt.
7. IF the user triggers a clipboard send on a Session and the local clipboard holds no text content, THEN THE Clipboard_Service SHALL send no clipboard Message, leave the local clipboard unchanged, and report an error indicating that the clipboard content type is unsupported.
8. THE Clipboard_Service SHALL accept clipboard Messages with a payload of up to 1 mebibyte of UTF-8 encoded content.
9. IF the user declines a pending clipboard entry, or if the 10 minute retention period of a pending clipboard entry elapses without a user decision, THEN THE Clipboard_Service SHALL discard the pending entry, leave the local clipboard unchanged, and stop prompting for that entry.
10. IF a received clipboard Message carries a payload larger than 1 mebibyte or a payload that is not valid UTF-8, THEN THE Clipboard_Service SHALL reject the Message, leave the local clipboard unchanged, and return an error Message that names the offending sequence number.
11. IF the user triggers a clipboard send on a Session and the local clipboard text content exceeds 1 mebibyte of UTF-8 encoded content, THEN THE Clipboard_Service SHALL send no clipboard Message and report an error indicating that the content exceeds the 1 mebibyte limit.

### Requirement 7: File Transfer

**User Story:** As a user, I want to send a file to another machine and know it arrived intact, so that I can stop emailing files to myself.

#### Acceptance Criteria

1. WHEN the user starts a Transfer on an active Session for a file whose byte size is at least 1 byte and at most 64 gibibytes, THE Transfer_Service SHALL send a transfer offer that carries the transfer identifier, the file name, the byte size, and the SHA-256 digest of the file content.
2. WHEN a transfer offer is accepted by the Peer, THE Transfer_Service SHALL send the file content as an ordered sequence of Chunks in ascending Chunk index order, each Chunk carrying the transfer identifier, the Chunk index, and the total Chunk count of the Transfer.
3. WHILE a Transfer is running, THE Transfer_Service SHALL report the transfer identifier, the count of acknowledged bytes, the total byte size, and the measured Goodput at intervals of 1 second or shorter.
4. WHEN the final Chunk of a Transfer is received, THE Transfer_Service SHALL compute the SHA-256 digest of the assembled content and compare the digest with the digest from the transfer offer.
5. IF the computed digest of an assembled Transfer differs from the offered digest, THEN THE Transfer_Service SHALL report an integrity failure that names the transfer identifier, the offered digest, and the computed digest, and discard the assembled content.
6. IF the assembled content of a failed Transfer cannot be discarded, THEN THE Transfer_Service SHALL report the integrity failure and report the retained content location.
7. IF a Chunk is not acknowledged within 10 seconds of being sent, THEN THE Transfer_Service SHALL resend that Chunk, and SHALL make at most 5 resend attempts for that Chunk.
8. WHEN a Transfer is resumed within 10 minutes of its interruption, THE Transfer_Service SHALL send only the Chunks that the receiver has not acknowledged, beginning at the lowest unacknowledged Chunk index.
9. WHEN the user cancels a running Transfer, THE Transfer_Service SHALL stop sending Chunks within 2 seconds of the cancel request and instruct the receiver to release the partial content held for that transfer identifier.
10. THE Transfer_Service SHALL select a Chunk size of 64 kibibytes for LAN_Transport and 512 bytes for BT_Transport.
11. IF a transfer offer is declined by the Peer, or receives neither an acceptance nor a decline within 60 seconds of being sent, THEN THE Transfer_Service SHALL end the Transfer without sending any Chunk and report the transfer identifier together with the reason of decline or offer timeout.
12. IF the user starts a Transfer for a file whose byte size is 0 bytes or larger than 64 gibibytes, THEN THE Transfer_Service SHALL reject the Transfer without sending a transfer offer and report an unsupported file size that names the measured byte size and the accepted range of 1 byte to 64 gibibytes.
13. IF a Chunk remains unacknowledged after 5 resend attempts, THEN THE Transfer_Service SHALL stop sending Chunks for that Transfer, report a transfer failure that names the transfer identifier and the Chunk index, and retain the acknowledged Chunk state of that Transfer for 10 minutes for resume.

### Requirement 8: Wire Protocol Encoding

**User Story:** As a developer, I want one exact wire format shared by every transport, so that a session behaves the same on Wi-Fi and on Bluetooth.

#### Acceptance Criteria

1. WHEN a Message is submitted for transmission on a Session, THE Message_Codec SHALL serialize that Message into a Wire_Frame that carries a protocol version, a Message type, a sequence number in the range 0 through 18,446,744,073,709,551,615, a payload length in the range 0 through 1,048,576 bytes, and exactly that count of payload bytes.
2. WHEN the count of payload bytes declared by a Wire_Frame has been received, THE Message_Codec SHALL parse that Wire_Frame into a Message that exposes the protocol version, the Message type, the sequence number, and the payload bytes.
3. WHEN a Message is serialized into a Wire_Frame and that Wire_Frame is parsed, THE Message_Codec SHALL produce a Message equal to the original Message in protocol version, type, sequence number, and payload bytes.
4. WHEN a Wire_Frame is parsed into a Message and that Message is serialized, THE Message_Codec SHALL produce a byte sequence equal to the original Wire_Frame.
5. IF a Wire_Frame declares a payload length that differs from the count of payload bytes received, THEN THE Message_Codec SHALL return a framing error that names the declared length and the received count, discard the received bytes of that Wire_Frame, and leave the Session Message sequence state unchanged.
6. IF a Wire_Frame declares a protocol version that the local Peer_Node does not support, THEN THE Message_Codec SHALL return a version error that names the declared version and the protocol version that the local Peer_Node accepts, and SHALL discard the Wire_Frame without delivering a Message to the Session.
7. THE Message_Codec SHALL parse Wire_Frame fields in the order protocol version, Message type, sequence number, payload length, payload bytes, and SHALL return the error for the first field that fails validation.
8. IF a Wire_Frame declares a Message type that the local Peer_Node does not recognize, THEN THE Peer_Node SHALL consume the declared count of payload bytes, continue parsing at the next Wire_Frame, keep the Session active, and record an unrecognized Message type event that names the declared type.
9. THE Message_Codec SHALL produce byte-identical Wire_Frames for the same Message on every serialization attempt and on both LAN_Transport and BT_Transport.
10. IF a Message submitted for serialization carries a payload larger than 1,048,576 bytes, THEN THE Message_Codec SHALL reject the serialization and return a payload size error that names the payload length and the 1,048,576 byte maximum.
11. IF a Wire_Frame declares a payload length greater than 1,048,576 bytes, THEN THE Message_Codec SHALL return a payload size error that names the declared length and the 1,048,576 byte maximum, and SHALL discard the received bytes of that Wire_Frame without buffering further payload bytes for it.
12. IF the declared count of payload bytes of a Wire_Frame has not been received within 10 seconds of the payload length field being parsed, THEN THE Message_Codec SHALL return a framing error that names the declared length and the received count and discard the received bytes of that Wire_Frame.

### Requirement 9: Pairing and Trust

**User Story:** As a user, I want only my own machines to reach my clipboard and files, so that a stranger on the same network cannot send or read data.

#### Acceptance Criteria

1. WHEN a Peer_Node starts and no long-term key pair is present in the local key store, THE Pairing_Service SHALL generate a long-term key pair and store the private key with file permissions that grant read and write access to the local user account only and no access to any other account.
2. IF the long-term key pair cannot be generated, or the private key cannot be stored with permissions that grant access to the local user account only, THEN THE Pairing_Service SHALL report a key setup failure that names the failing step, and THE Peer_Node SHALL reject every Session request until the key pair is stored with those permissions.
3. WHEN the user starts pairing with a Peer, THE Pairing_Service SHALL display a verification code of exactly 6 decimal digits derived from both Peer_Nodes' public keys, SHALL display the identical code on both Peer_Nodes for the same public key pair, and SHALL treat the code as valid for 120 seconds from display.
4. WHEN the user confirms on both Peer_Nodes within the 120-second validity window that the displayed verification codes match, THE Pairing_Service SHALL add each Peer's public key to the local trust store as a Trusted_Peer, keeping exactly one entry per public key fingerprint.
5. IF the user reports on either Peer_Node that the displayed verification codes do not match, or if confirmation is not received on both Peer_Nodes within the 120-second validity window, THEN THE Pairing_Service SHALL abandon the pairing attempt, discard the public key received during that attempt, add no Trusted_Peer entry, leave existing trust store entries unchanged, and report a pairing failure that names the affected Peer.
6. IF a Session is requested by a Peer that is not a Trusted_Peer, THEN THE Peer_Node SHALL reject the Session within 1 second of the request, deliver no Message payload from that Peer, and prompt the user to start pairing with that Peer.
7. IF the public key presented by a Trusted_Peer differs from the stored public key for that Peer, THEN THE Peer_Node SHALL reject the Session, retain the stored public key unchanged, and report a key mismatch that names the affected Peer.
8. WHEN the user removes a Trusted_Peer, THE Pairing_Service SHALL delete the stored public key for that Peer, close any Session with that Peer within 2 seconds, and reject subsequent Session requests from that Peer until pairing with that Peer completes again.
9. THE Pairing_Service SHALL delete a stored public key only in response to a user removal request.
10. THE Pairing_Service SHALL retain each Trusted_Peer entry across Peer_Node restarts until the user removes that entry, SHALL store at least 32 Trusted_Peer entries, and SHALL load the stored entries before accepting the first Session request after a restart.
11. IF the trust store cannot be read or fails its integrity check at Peer_Node start, THEN THE Pairing_Service SHALL report a trust store failure, retain the stored trust store content without modification, and THE Peer_Node SHALL reject every Session request until the trust store is readable and passes its integrity check.

### Requirement 10: Confidentiality in Transit

**User Story:** As a user, I want my messages and files encrypted on the wire, so that anyone observing the network or the Bluetooth link learns nothing.

#### Acceptance Criteria

1. WHEN a Session is established, THE Peer_Node SHALL complete an authenticated key exchange that binds the Session keys to the long-term public key stored for that Trusted_Peer and to the local Peer_Node's long-term public key, before sending or accepting any Message other than the key exchange Messages of that Session.
2. THE Peer_Node SHALL encrypt the payload of every Message, including text, clipboard, transfer offer, Chunk, acknowledgement, error, and keepalive Messages, with an authenticated encryption algorithm using the Session keys, such that no payload byte appears in the Wire_Frame payload field in plaintext.
3. IF a received Message fails its authentication tag check, THEN THE Peer_Node SHALL discard the Message without delivering its payload to any Service and without applying the Message to Session state, on the first failure and with no retry.
4. WHEN a Session is rebound to another Transport, THE Peer_Node SHALL continue using the Session keys negotiated at Session establishment without performing a new key exchange.
5. THE Peer_Node SHALL derive a fresh set of Session keys for each new Session and SHALL NOT reuse key material from any previous or concurrent Session.
6. THE Peer_Node SHALL exclude Message payload content, clipboard content, file content, and Session keys from every event log entry and error report, and SHALL limit logged per-Message detail to Message type, sequence number, and payload length.
7. WHEN a received Message fails its authentication tag check, THE Peer_Node SHALL close the Session and report an authentication failure that names the Session identifier and the affected Peer.
8. IF the authenticated key exchange for a Session does not complete within 5 seconds of the Transport connection opening, THEN THE Peer_Node SHALL abandon the Session establishment, leave no Session in an active state, and report a key exchange failure that names the affected Peer and the attempted Transport.
9. IF a Wire_Frame carrying a Message type other than a key exchange Message is received before the authenticated key exchange for that connection completes, THEN THE Peer_Node SHALL discard the Wire_Frame without parsing its payload, close the connection, and report a protocol violation that names the affected Peer.

### Requirement 11: Performance Targets

**User Story:** As a user, I want transfers and messages to feel immediate, so that using two machines feels like using one.

#### Acceptance Criteria

1. WHILE a Session uses LAN_Transport on a Reference_LAN, THE Peer_Node SHALL deliver text Messages carrying up to 1 kibibyte of payload with a 95th percentile end-to-end latency of 100 milliseconds or less, where end-to-end latency is the interval from the sending Peer_Node accepting the user's text submission to the receiving Peer_Node making the Message available for display, measured over a sample of at least 100 consecutive text Messages.
2. WHILE a Transfer of a file of 100 mebibytes or larger runs on LAN_Transport on a Reference_LAN, THE Transfer_Service SHALL sustain a Goodput of 40 mebibytes per second or higher, measured as the mean Goodput over every 5-second window that begins 2 seconds or more after the first Chunk of that Transfer is sent.
3. WHILE a Transfer of a file of 1 mebibyte or larger runs on BT_Transport between two machines separated by 2 metres or less with no intervening obstruction, THE Transfer_Service SHALL sustain a Goodput of 40 kibibytes per second or higher, measured as the mean Goodput over every 30-second window that begins 5 seconds or more after the first Chunk of that Transfer is sent.
4. WHEN a Session is requested on LAN_Transport between two Trusted_Peers on a Reference_LAN, THE Peer_Node SHALL complete Transport connection, authenticated key exchange, and transition of the Session to the active state within 500 milliseconds of the request.
5. IF a Session requested on LAN_Transport between two Trusted_Peers on a Reference_LAN does not reach the active state within 500 milliseconds of the request, THEN THE Peer_Node SHALL abandon the establishment attempt, release the partially established Session, and report an establishment timeout that names the Peer and the elapsed time.
6. WHILE 8 Sessions are active on LAN_Transport with 1 running Transfer, THE Peer_Node SHALL keep resident memory use at or below 300 mebibytes at every sample taken at 1-second intervals.
7. WHILE every active Session has sent and received no Message for 60 seconds or longer, THE Peer_Node SHALL keep processor use at or below 1 percent of one core, measured as the mean over each 60-second window.
8. IF the measured Goodput of a running Transfer stays below the target Goodput of the active Transport for a continuous 10-second window, THEN THE Transfer_Service SHALL report a degraded throughput condition that names the active Transport, the measured Goodput, and the target Goodput.
9. IF a degraded throughput condition is reported for a running Transfer, THEN THE Transfer_Service SHALL continue that Transfer and keep the Session active.

### Requirement 12: Minimal Cross-Platform Footprint

**User Story:** As a user, I want a single small binary per machine, so that I can run this on a Mac and on a Windows laptop without installing a runtime stack.

#### Acceptance Criteria

1. WHEN the user launches the Peer_Node executable on macOS 13 or later, Windows 11, or Ubuntu 22.04 or later with no runtime, interpreter, or framework installed beyond the components shipped with that operating system, THE Peer_Node SHALL reach a ready state that accepts user commands within 5 seconds.
2. THE Peer_Node SHALL be distributed as one self-contained executable for each combination of supported operating system and processor architecture, covering x86-64 and arm64, where each executable requires no files other than itself and components shipped with the host operating system.
3. WHERE the host operating system exposes no Bluetooth interface that the Peer_Node can use, THE Peer_Node SHALL complete startup with LAN_Transport as its only candidate Transport and report that BT_Transport is unavailable.
4. WHERE the host operating system is macOS, WHEN the user requests a manual AirDrop handoff for a file that exists and is readable by the Peer_Node, THE Peer_Node SHALL open the operating system share interface with that file selected within 5 seconds and keep every active Session in its current state.
5. IF the user requests a manual AirDrop handoff on a host operating system other than macOS, THEN THE Peer_Node SHALL reject the request, leave the named file unchanged, and report that AirDrop handoff is available on macOS only.
6. THE Peer_Node SHALL expose every capability defined in Requirements 1 through 11, covering discovery, pairing, Session management, text messaging, clipboard sharing, file transfer, and status reporting, as a command line command that requires no graphical interface.
7. THE Peer_Node SHALL be distributed as executables of 50 mebibytes or less each.
8. IF the host operating system exposes no Bluetooth interface that the Peer_Node can use and no reachable IP network interface, THEN THE Peer_Node SHALL complete startup with no candidate Transport and report that both LAN_Transport and BT_Transport are unavailable.
9. IF the user requests a manual AirDrop handoff for a file that does not exist or that the Peer_Node cannot read, THEN THE Peer_Node SHALL leave the operating system share interface unopened and report an error naming the requested file and the reason the file is unusable.

### Requirement 13: Visibility and Error Reporting

**User Story:** As a user whose transfer just stalled, I want to see which transport is in use and what failed, so that I can tell whether to move closer or check the network.

#### Acceptance Criteria

1. WHILE a Session is active and the Peer display name, the name of the active Transport, the measured Goodput in bytes per second, and the measured round-trip time in milliseconds of that Session are all available, THE Peer_Node SHALL display all four values for that Session and SHALL refresh the displayed values at intervals of 1 second or shorter.
2. IF any of the Peer display name, the name of the active Transport, the measured Goodput, or the measured round-trip time of a Session is unavailable, THEN THE Peer_Node SHALL display a pending state for that Session in place of all four values and SHALL replace the pending state with the four values within 1 second of all four values becoming available.
3. WHEN a Session changes its active Transport, THE Peer_Node SHALL display, within 1 second of the change, the name of the previous Transport, the name of the new Transport, and a change reason that is one of: the previous Transport was marked unavailable, a higher ranked Transport became available, or the user pinned the Session to a named Transport.
4. IF a Session establishment, a Transport connection attempt, a Message delivery, a Transfer, or a clipboard apply fails, THEN THE Peer_Node SHALL report, within 1 second of the failure, the name of the failing operation, the display name of the affected Peer, the failure reason, and one remediation step that names a user action, and SHALL keep every other Session in its current state.
5. WHEN a Session is established, a Session changes its active Transport, a Transfer completes, or a Session is rejected, THE Peer_Node SHALL write one event log entry within 1 second of the event that carries the event timestamp, the event type, the affected Peer's display name and public key fingerprint, and the event outcome, and that excludes Message payload content.
6. WHEN the acknowledged byte count of a running Transfer does not increase for 10 consecutive seconds, THE Peer_Node SHALL display a stall indication that names the transfer identifier, the name of the active Transport, the most recently measured Goodput, and the most recently measured round-trip time.
7. IF the Peer_Node cannot write an event log entry, THEN THE Peer_Node SHALL report a log write failure that names the event type and the failure reason, and SHALL keep every Session in its current state.

## Out of Scope

- A relay or rendezvous server for peers separated by the public internet with no Bluetooth link. Version 1 covers shared-network and Bluetooth paths only.
- NAT traversal, hole punching, and TURN-style relaying.
- Programmatic control of AirDrop. AirDrop appears only as a manual handoff to the macOS share interface.
- Clipboard formats other than plain text, including images, styled text, and file promises.
- Graphical user interface. The command line interface is the version 1 surface.
- Group chat semantics such as shared history, rooms, or offline message storage on a third party.
- Mobile platforms, including iOS and Android.

## Open Questions

1. **Implementation language.** Go, Rust, and Node.js each satisfy Requirement 12. Go gives one static binary and a simple concurrency model with mature mDNS libraries; Rust gives the best chance of hitting Requirement 11 targets with the smallest binary; Node.js is fastest to prototype but conflicts with the single self-contained executable goal of Requirement 12.2. Recommendation: Go.
2. **Bluetooth layer.** Bluetooth LE is available through cross-platform libraries but caps Goodput far below the 40 kibibytes per second target of Requirement 11.3 unless L2CAP connection-oriented channels are used. Bluetooth Classic RFCOMM is faster but has thinner cross-platform library support. Which tradeoff do you want first?
3. **Concurrent Session count.** Requirement 4.1 sets the ceiling at 8, and Requirement 4.9 rejects a ninth Session at that limit. Confirm whether your real fleet is smaller, since a lower bound simplifies the design.
4. **Continuous clipboard sync default.** Requirement 6.5 makes continuous sync opt-in per Session, and Requirement 6.3 makes manual confirmation the behaviour when automatic apply is disabled. Confirm that opt-in, rather than always-on, matches how you want to use it.
