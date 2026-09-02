// Package lan is the IP network I/O adapter. It implements the Transport and
// TransportConnection interfaces declared in internal/core/transport on top of
// net.TCPConn and net.TCPListener, and it carries presence announcements over
// an IPv4 multicast UDP beacon, enumerating interfaces with net.Interfaces.
//
// Only the sockets live here. Announcement encoding and validation, the peer
// registry, transport ranking, and the switch policy all stay in core; this
// package moves bytes and reports availability.
package lan
