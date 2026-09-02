# macOS native shim

Holds `peerbeam_bt_macos.m`, the Objective-C Bluetooth shim reached over cgo from
`internal/platform/bt`. It uses **IOBluetooth** for Bluetooth Classic RFCOMM stream
sockets, with CoreBluetooth (BLE L2CAP connection-oriented channels) as the fallback
for hardware where Classic is unavailable. The same file also exposes the
`NSSharingServicePicker` share sheet entry point used by `internal/platform/share`.
