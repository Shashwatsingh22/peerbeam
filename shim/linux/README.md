# Linux native shim

Holds `peerbeam_bt_linux.c`, the C Bluetooth shim reached over cgo from
`internal/platform/bt`. It uses **BlueZ** through an `AF_BLUETOOTH` RFCOMM socket, an
address family the Go standard library cannot open. BlueZ also has a D-Bus API that
could be driven from pure Go, but the socket shim keeps all three platforms on one
interface.
