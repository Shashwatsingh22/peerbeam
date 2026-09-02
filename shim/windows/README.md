# Windows native shim

Holds `peerbeam_bt_win.c`, the C Bluetooth shim reached over cgo from
`internal/platform/bt`. It uses **Winsock Bluetooth sockets** (`AF_BTH` with RFCOMM),
which the Go standard library cannot open, exposing the same advertise, scan, connect,
read, write, and close entry points as the other platforms.
