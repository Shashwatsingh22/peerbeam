// peerbeam-bt-shim: the macOS Bluetooth helper for internal/platform/bt.
//
// This is Option B from the design: a standalone executable speaking the length-prefixed shim
// frame protocol over stdin and stdout. The Go side (ShimBluetoothBridge) is already written and
// tested against this protocol, so nothing in Go changes when this lands.
//
// Why Bluetooth LE rather than Classic RFCOMM, which shim/macos/README.md originally named:
// IOBluetooth's RFCOMM stack needs an SDP service record and an OS-level pairing between the two
// machines before a channel can open, and Apple has been retiring the Classic serial profiles.
// CoreBluetooth needs neither - two machines find each other by service UUID and open a channel
// with no pairing dance - and it is the supported API on current macOS. L2CAP connection-oriented
// channels give a real bidirectional byte stream, which is exactly what BluetoothBridge wants;
// GATT characteristic writes would have meant reimplementing framing and flow control on top of a
// request/response protocol.
//
// Each machine runs both roles at once:
//
//   peripheral  advertises the service UUID, serves the announcement record and the L2CAP PSM as
//               GATT characteristics, and accepts inbound channels
//   central     scans for the service UUID, reads a discovered peer's record, and opens outbound
//               channels
//
// The announcement record is up to 2048 bytes (discovery.MaxAnnouncementBytes) and a BLE
// advertisement carries about 31, so the advertisement is only the service UUID plus a short
// local name, and the full record is read over GATT once a peer is discovered. That extra read is
// what the 15-second discovery budget in Req 1.4 pays for.

import CoreBluetooth
import Foundation

// MARK: - Shim frame protocol

/// Frame kinds, matching the constants in internal/platform/bt/shimbridge.go. The set is closed:
/// there is no version negotiation with a helper the node started itself, so an unrecognised kind
/// is a protocol error rather than something to skip.
enum ShimKind: UInt8 {
    case startAdvertising = 1
    case stopAdvertising = 2
    case scan = 3
    case scanResult = 4
    case scanDone = 5
    case connect = 6
    case connected = 7
    case accepted = 8
    case data = 9
    case close = 10
    case error = 11
    case available = 12
}

let shimFrameHeaderBytes = 9
let shimMaxPayloadBytes = 64 * 1024

/// Inbound streams are numbered by the shim, outbound ones by Go. Go counts up from 1, so setting
/// the high bit here keeps the two allocators from ever colliding on one id.
let shimInboundStreamIdBase: UInt32 = 0x8000_0000

// MARK: - Service identifiers

// "PEER" and "BEAM" in ASCII hex, so these are recognisable in a packet trace.
let peerbeamServiceUUID = CBUUID(string: "50454552-4245-414D-0000-000000000001")
let peerbeamRecordUUID = CBUUID(string: "50454552-4245-414D-0000-000000000002")
let peerbeamPSMUUID = CBUUID(string: "50454552-4245-414D-0000-000000000003")

// MARK: - Logging

/// Diagnostics go to stderr. The Go side wires the shim's stderr to its own, so a native failure
/// is visible rather than swallowed. stdout carries frames only - a stray print there would
/// desynchronise the protocol for good.
func log(_ message: String) {
    FileHandle.standardError.write("peerbeam-bt-shim: \(message)\n".data(using: .utf8)!)
}

// MARK: - Frame writing

/// Serialises frames onto stdout.
///
/// The lock matters: a partial frame interleaved with another would desynchronise the Go reader
/// permanently, and writes originate from both the CoreBluetooth callbacks and the stdin reader
/// thread.
final class FrameWriter {
    static let shared = FrameWriter()

    private let handle = FileHandle.standardOutput
    private let lock = NSLock()

    func send(_ kind: ShimKind, streamId: UInt32 = 0, payload: Data = Data()) {
        guard payload.count <= shimMaxPayloadBytes else {
            log("refusing to send a \(payload.count)-byte payload, over the \(shimMaxPayloadBytes)-byte maximum")
            return
        }

        var frame = Data(capacity: shimFrameHeaderBytes + payload.count)
        frame.append(kind.rawValue)
        frame.appendBigEndian(streamId)
        frame.appendBigEndian(UInt32(payload.count))
        frame.append(payload)

        lock.lock()
        defer { lock.unlock() }
        // write(contentsOf:) throws on a closed pipe, which is the normal shutdown path when the
        // node exits first. Nothing useful remains to be done, so it ends the process.
        do {
            try handle.write(contentsOf: frame)
        } catch {
            exit(0)
        }
    }

    func sendError(_ streamId: UInt32, _ message: String) {
        send(.error, streamId: streamId, payload: Data(message.utf8))
    }
}

extension Data {
    mutating func appendBigEndian(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }

    func bigEndianUInt32(at offset: Int) -> UInt32 {
        (UInt32(self[offset]) << 24) | (UInt32(self[offset + 1]) << 16)
            | (UInt32(self[offset + 2]) << 8) | UInt32(self[offset + 3])
    }
}

// MARK: - L2CAP stream pumping

/// One open L2CAP channel, pumped between CoreBluetooth's Foundation streams and shim frames.
///
/// Writes are buffered rather than issued directly. An OutputStream accepts bytes only while it
/// reports space available, so a write larger than the current window has to be held and resumed
/// from the delegate callback. Dropping the remainder would silently truncate a Wire_Frame.
final class L2CAPStream: NSObject, StreamDelegate {
    let streamId: UInt32
    private let channel: CBL2CAPChannel
    private let input: InputStream
    private let output: OutputStream

    private var pendingWrites = Data()
    private var closed = false
    private var readBuffer = [UInt8](repeating: 0, count: 4096)

    /// Called when the channel ends, so the owner can drop it from its table.
    var onClosed: ((UInt32) -> Void)?

    init?(streamId: UInt32, channel: CBL2CAPChannel) {
        guard let input = channel.inputStream, let output = channel.outputStream else {
            return nil
        }
        self.streamId = streamId
        self.channel = channel
        self.input = input
        self.output = output
        super.init()

        // Scheduled on the main run loop because every other moving part here - the
        // CoreBluetooth callbacks and the command dispatch - is already on it. One thread means
        // the stream table needs no locking.
        input.delegate = self
        output.delegate = self
        input.schedule(in: .main, forMode: .default)
        output.schedule(in: .main, forMode: .default)
        input.open()
        output.open()
    }

    func stream(_ stream: Stream, handle event: Stream.Event) {
        switch event {
        case .hasBytesAvailable:
            drainInput()
        case .hasSpaceAvailable:
            flushPending()
        case .endEncountered:
            closeAndReport()
        case .errorOccurred:
            let reason = stream.streamError?.localizedDescription ?? "l2cap stream error"
            FrameWriter.shared.sendError(streamId, reason)
            closeAndReport()
        default:
            break
        }
    }

    private func drainInput() {
        while input.hasBytesAvailable {
            let read = input.read(&readBuffer, maxLength: readBuffer.count)
            if read > 0 {
                FrameWriter.shared.send(.data, streamId: streamId, payload: Data(readBuffer[0..<read]))
                continue
            }
            // 0 is a clean end of stream; negative is a read error. Either way the channel is
            // finished, and endEncountered may not arrive after an error.
            if read <= 0 {
                closeAndReport()
            }
            return
        }
    }

    /// Queues a payload and writes as much as the channel currently accepts.
    func write(_ payload: Data) {
        guard !closed else {
            FrameWriter.shared.sendError(streamId, "write to a closed bluetooth channel")
            return
        }
        pendingWrites.append(payload)
        flushPending()
    }

    private func flushPending() {
        while !pendingWrites.isEmpty && output.hasSpaceAvailable {
            let written = pendingWrites.withUnsafeBytes { raw -> Int in
                guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                return output.write(base, maxLength: pendingWrites.count)
            }
            if written > 0 {
                pendingWrites.removeFirst(written)
                continue
            }
            if written < 0 {
                let reason = output.streamError?.localizedDescription ?? "l2cap write failed"
                FrameWriter.shared.sendError(streamId, reason)
                closeAndReport()
            }
            return
        }
    }

    /// Closes the channel without emitting a close frame, for when Go asked for the close.
    func closeQuietly() {
        guard !closed else { return }
        closed = true
        tearDown()
    }

    private func closeAndReport() {
        guard !closed else { return }
        closed = true
        tearDown()
        FrameWriter.shared.send(.close, streamId: streamId)
        onClosed?(streamId)
    }

    private func tearDown() {
        input.close()
        output.close()
        input.remove(from: .main, forMode: .default)
        output.remove(from: .main, forMode: .default)
        input.delegate = nil
        output.delegate = nil
    }
}

// MARK: - The shim

/// Holds both Bluetooth roles and the stream table.
///
/// Everything runs on the main queue: the CoreBluetooth managers are created with a nil queue, the
/// streams are scheduled on the main run loop, and the stdin reader dispatches each command onto
/// it. That is what lets the mutable state below be plain properties rather than lock-guarded.
final class BluetoothShim: NSObject {
    private var peripheralManager: CBPeripheralManager!
    private var centralManager: CBCentralManager!

    // Peripheral role.
    private var advertisedRecord = Data()
    private var wantsAdvertising = false
    private var serviceAdded = false
    private var publishedPSM: CBL2CAPPSM?
    private var psmPublishRequested = false

    // Central role.
    private var wantsScan = false
    /// Peripherals seen in the current scan, by identifier string. Held so a later Connect can
    /// dial one: CoreBluetooth will not connect to a peripheral it did not hand out.
    private var discovered: [String: CBPeripheral] = [:]
    /// Peripherals whose record has already been reported this scan, so a repeated advertisement
    /// does not cause a second GATT read.
    private var recordReported: Set<String> = []
    /// GATT connections opened purely to read a record.
    private var readingRecord: Set<String> = []
    /// Outbound connects awaiting an L2CAP channel: peripheral identifier to Go's stream id.
    private var pendingConnects: [String: UInt32] = [:]

    private var streams: [UInt32: L2CAPStream] = [:]
    private var nextInboundStreamId = shimInboundStreamIdBase

    private var reportedAvailability: Bool?

    func start() {
        peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    // MARK: Commands from Go

    func handle(kind: ShimKind, streamId: UInt32, payload: Data) {
        switch kind {
        case .startAdvertising:
            advertisedRecord = payload
            wantsAdvertising = true
            configurePeripheral()
        case .stopAdvertising:
            wantsAdvertising = false
            if peripheralManager.isAdvertising {
                peripheralManager.stopAdvertising()
            }
        case .scan:
            wantsScan = true
            beginScan()
        case .connect:
            guard let deviceId = String(data: payload, encoding: .utf8), !deviceId.isEmpty else {
                FrameWriter.shared.sendError(streamId, "connect carried no device id")
                return
            }
            connect(deviceId: deviceId, streamId: streamId)
        case .data:
            guard let stream = streams[streamId] else {
                FrameWriter.shared.sendError(streamId, "no such bluetooth stream")
                return
            }
            stream.write(payload)
        case .close:
            if let stream = streams.removeValue(forKey: streamId) {
                stream.closeQuietly()
            }
        default:
            log("ignoring a frame of kind \(kind.rawValue), which only travels shim to node")
        }
    }

    // MARK: Availability

    /// Reports availability once per change. Go treats this as "does this host have usable
    /// Bluetooth", which is the Req 12.3 decision, so it must not flap on transient states like
    /// .resetting or .unknown while the managers come up.
    private func reportAvailability() {
        let usable = centralManager?.state == .poweredOn && peripheralManager?.state == .poweredOn
        guard reportedAvailability != usable else { return }
        reportedAvailability = usable
        FrameWriter.shared.send(.available, payload: Data([usable ? 1 : 0]))
        if !usable {
            log("bluetooth is not available: central=\(stateName(centralManager?.state)) peripheral=\(stateName(peripheralManager?.state))")
        }
    }

    private func stateName(_ state: CBManagerState?) -> String {
        switch state {
        case .some(.poweredOn): return "poweredOn"
        case .some(.poweredOff): return "poweredOff"
        case .some(.unauthorized): return "unauthorized"
        case .some(.unsupported): return "unsupported"
        case .some(.resetting): return "resetting"
        case .some(.unknown): return "unknown"
        default: return "nil"
        }
    }

    // MARK: Peripheral role

    private func configurePeripheral() {
        guard peripheralManager.state == .poweredOn, wantsAdvertising else { return }

        if !serviceAdded {
            let record = CBMutableCharacteristic(
                type: peerbeamRecordUUID, properties: [.read], value: nil,
                permissions: [.readable])
            let psm = CBMutableCharacteristic(
                type: peerbeamPSMUUID, properties: [.read], value: nil, permissions: [.readable])
            let service = CBMutableService(type: peerbeamServiceUUID, primary: true)
            service.characteristics = [record, psm]
            peripheralManager.add(service)
            serviceAdded = true
        }

        // withEncryption: false because the session above already encrypts every payload with
        // ChaCha20-Poly1305 keyed by the handshake. Requiring link-layer encryption here would
        // force an OS pairing prompt on both machines and buy nothing the session does not
        // already provide.
        if publishedPSM == nil && !psmPublishRequested {
            psmPublishRequested = true
            peripheralManager.publishL2CAPChannel(withEncryption: false)
        }

        startAdvertisingIfReady()
    }

    private func startAdvertisingIfReady() {
        guard peripheralManager.state == .poweredOn, wantsAdvertising, publishedPSM != nil else {
            return
        }
        if peripheralManager.isAdvertising {
            peripheralManager.stopAdvertising()
        }
        // Only the service UUID and a short name fit an advertisement; the record itself is
        // served over GATT. macOS ignores service data and manufacturer data in
        // startAdvertising, so there is no point putting the fingerprint here.
        peripheralManager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [peerbeamServiceUUID],
            CBAdvertisementDataLocalNameKey: "peerbeam",
        ])
    }

    // MARK: Central role

    private func beginScan() {
        guard centralManager.state == .poweredOn, wantsScan else { return }
        recordReported.removeAll()
        // Duplicate keys off: one advertisement per peripheral is enough, since the record is
        // read over GATT rather than parsed from the advertisement.
        centralManager.scanForPeripherals(
            withServices: [peerbeamServiceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    }

    private func connect(deviceId: String, streamId: UInt32) {
        guard let peripheral = discovered[deviceId] else {
            FrameWriter.shared.sendError(
                streamId, "bluetooth device \(deviceId) has not been discovered by this shim")
            return
        }
        pendingConnects[deviceId] = streamId
        if peripheral.state == .connected {
            openChannel(on: peripheral)
        } else {
            centralManager.connect(peripheral, options: nil)
        }
    }

    /// Reads the peer's PSM, then opens the channel. The PSM is per-peer and only known after the
    /// remote published its channel, so it cannot be a constant.
    private func openChannel(on peripheral: CBPeripheral) {
        if let psm = knownPSM[peripheral.identifier.uuidString] {
            peripheral.openL2CAPChannel(psm)
            return
        }
        peripheral.delegate = self
        if let service = peripheral.services?.first(where: { $0.uuid == peerbeamServiceUUID }) {
            discoverOrRead(peripheral: peripheral, service: service)
        } else {
            peripheral.discoverServices([peerbeamServiceUUID])
        }
    }

    private var knownPSM: [String: CBL2CAPPSM] = [:]

    private func discoverOrRead(peripheral: CBPeripheral, service: CBService) {
        guard let characteristics = service.characteristics, !characteristics.isEmpty else {
            peripheral.discoverCharacteristics(
                [peerbeamRecordUUID, peerbeamPSMUUID], for: service)
            return
        }
        let identifier = peripheral.identifier.uuidString
        // A connection opened to read a record wants the record; one opened by Connect wants the
        // PSM. Both are cheap reads, so the wanted one is requested and the other ignored.
        if readingRecord.contains(identifier),
            let record = characteristics.first(where: { $0.uuid == peerbeamRecordUUID })
        {
            peripheral.readValue(for: record)
        }
        if pendingConnects[identifier] != nil,
            let psm = characteristics.first(where: { $0.uuid == peerbeamPSMUUID })
        {
            peripheral.readValue(for: psm)
        }
    }

    // MARK: Streams

    private func adopt(channel: CBL2CAPChannel, streamId: UInt32, inbound: Bool) {
        guard let stream = L2CAPStream(streamId: streamId, channel: channel) else {
            FrameWriter.shared.sendError(streamId, "l2cap channel exposed no streams")
            return
        }
        stream.onClosed = { [weak self] id in self?.streams.removeValue(forKey: id) }
        streams[streamId] = stream
        FrameWriter.shared.send(inbound ? .accepted : .connected, streamId: streamId)
    }
}

// MARK: - CBPeripheralManagerDelegate

extension BluetoothShim: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        reportAvailability()
        if peripheral.state == .poweredOn {
            configurePeripheral()
        }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager, didPublishL2CAPChannel PSM: CBL2CAPPSM, error: Error?
    ) {
        if let error {
            psmPublishRequested = false
            log("publishing an l2cap channel failed: \(error.localizedDescription)")
            return
        }
        publishedPSM = PSM
        log("published l2cap psm \(PSM)")
        startAdvertisingIfReady()
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?
    ) {
        if let error {
            log("adding the gatt service failed: \(error.localizedDescription)")
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error {
            log("advertising failed: \(error.localizedDescription)")
            return
        }
        log("advertising \(peerbeamServiceUUID.uuidString)")
    }

    /// Serves the record and the PSM. The offset handling is required: a 2048-byte record does not
    /// fit one ATT response, so CoreBluetooth issues a series of reads at increasing offsets.
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        let value: Data
        switch request.characteristic.uuid {
        case peerbeamRecordUUID:
            value = advertisedRecord
        case peerbeamPSMUUID:
            guard let psm = publishedPSM else {
                peripheral.respond(to: request, withResult: .unlikelyError)
                return
            }
            value = Data([UInt8((psm >> 8) & 0xFF), UInt8(psm & 0xFF)])
        default:
            peripheral.respond(to: request, withResult: .attributeNotFound)
            return
        }

        guard request.offset <= value.count else {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }
        request.value = value.subdata(in: request.offset..<value.count)
        peripheral.respond(to: request, withResult: .success)
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager, didOpen channel: CBL2CAPChannel?, error: Error?
    ) {
        guard let channel, error == nil else {
            log("an inbound l2cap channel failed: \(error?.localizedDescription ?? "unknown")")
            return
        }
        nextInboundStreamId += 1
        adopt(channel: channel, streamId: nextInboundStreamId, inbound: true)
    }
}

// MARK: - CBCentralManagerDelegate

extension BluetoothShim: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        reportAvailability()
        if central.state == .poweredOn {
            beginScan()
        }
    }

    func centralManager(
        _ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any], rssi RSSI: NSNumber
    ) {
        let identifier = peripheral.identifier.uuidString
        discovered[identifier] = peripheral

        // The record has to be read over GATT, which needs a connection. Skip peers already
        // reported this scan and those mid-read.
        guard !recordReported.contains(identifier), !readingRecord.contains(identifier) else {
            return
        }
        readingRecord.insert(identifier)
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        peripheral.discoverServices([peerbeamServiceUUID])
    }

    func centralManager(
        _ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?
    ) {
        let identifier = peripheral.identifier.uuidString
        readingRecord.remove(identifier)
        if let streamId = pendingConnects.removeValue(forKey: identifier) {
            FrameWriter.shared.sendError(
                streamId, error?.localizedDescription ?? "bluetooth connect failed")
        }
    }

    func centralManager(
        _ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?
    ) {
        let identifier = peripheral.identifier.uuidString
        readingRecord.remove(identifier)
        knownPSM.removeValue(forKey: identifier)
        if let streamId = pendingConnects.removeValue(forKey: identifier) {
            FrameWriter.shared.sendError(
                streamId, error?.localizedDescription ?? "the bluetooth peer disconnected")
        }
    }
}

// MARK: - CBPeripheralDelegate

extension BluetoothShim: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error {
            failPeripheral(peripheral, error.localizedDescription)
            return
        }
        guard let service = peripheral.services?.first(where: { $0.uuid == peerbeamServiceUUID })
        else {
            failPeripheral(peripheral, "the peer does not expose the peerbeam service")
            return
        }
        peripheral.discoverCharacteristics([peerbeamRecordUUID, peerbeamPSMUUID], for: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?
    ) {
        if let error {
            failPeripheral(peripheral, error.localizedDescription)
            return
        }
        discoverOrRead(peripheral: peripheral, service: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        if let error {
            failPeripheral(peripheral, error.localizedDescription)
            return
        }
        let identifier = peripheral.identifier.uuidString

        switch characteristic.uuid {
        case peerbeamRecordUUID:
            readingRecord.remove(identifier)
            guard let record = characteristic.value, !record.isEmpty else {
                return
            }
            recordReported.insert(identifier)
            // Payload is the device id, a null byte, then the record, which is what
            // splitDeviceRecord in shimbridge.go expects.
            var payload = Data(identifier.utf8)
            payload.append(0)
            payload.append(record)
            FrameWriter.shared.send(.scanResult, payload: payload)

            // Nothing else is wanted from this peer unless a Connect is outstanding. Dropping the
            // GATT link keeps the radio free; the identifier stays in `discovered` so a later
            // Connect can still dial it.
            if pendingConnects[identifier] == nil {
                centralManager.cancelPeripheralConnection(peripheral)
            }

        case peerbeamPSMUUID:
            guard let value = characteristic.value, value.count >= 2 else {
                failPeripheral(peripheral, "the peer reported no l2cap psm")
                return
            }
            let psm = CBL2CAPPSM(UInt16(value[0]) << 8 | UInt16(value[1]))
            knownPSM[identifier] = psm
            peripheral.openL2CAPChannel(psm)

        default:
            break
        }
    }

    func peripheral(
        _ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?
    ) {
        let identifier = peripheral.identifier.uuidString
        guard let streamId = pendingConnects.removeValue(forKey: identifier) else {
            // An outbound channel nobody asked for. Closing it is the only sane response.
            log("opened an l2cap channel with no pending connect")
            return
        }
        guard let channel, error == nil else {
            FrameWriter.shared.sendError(
                streamId, error?.localizedDescription ?? "opening the l2cap channel failed")
            return
        }
        adopt(channel: channel, streamId: streamId, inbound: false)
    }

    private func failPeripheral(_ peripheral: CBPeripheral, _ reason: String) {
        let identifier = peripheral.identifier.uuidString
        readingRecord.remove(identifier)
        if let streamId = pendingConnects.removeValue(forKey: identifier) {
            FrameWriter.shared.sendError(streamId, reason)
        }
        centralManager.cancelPeripheralConnection(peripheral)
    }
}

// MARK: - stdin reader

/// Reads frames from Go on a background thread and dispatches each onto the main queue.
///
/// Blocking reads on a dedicated thread rather than a DispatchSource: the protocol is strictly
/// framed, so reading exactly the header and then exactly the payload is simpler to get right than
/// an event-driven partial-buffer reader, and the thread costs nothing.
func startReadingCommands(shim: BluetoothShim) {
    let thread = Thread {
        let stdin = FileHandle.standardInput

        func readExactly(_ count: Int) -> Data? {
            var collected = Data()
            while collected.count < count {
                guard let piece = try? stdin.read(upToCount: count - collected.count),
                    !piece.isEmpty
                else {
                    return nil
                }
                collected.append(piece)
            }
            return collected
        }

        while true {
            guard let header = readExactly(shimFrameHeaderBytes) else { break }
            let rawKind = header[0]
            let streamId = header.bigEndianUInt32(at: 1)
            let length = Int(header.bigEndianUInt32(at: 5))

            guard length <= shimMaxPayloadBytes else {
                log("the node declared a \(length)-byte payload, over the maximum; exiting")
                break
            }
            var payload = Data()
            if length > 0 {
                guard let body = readExactly(length) else { break }
                payload = body
            }
            guard let kind = ShimKind(rawValue: rawKind) else {
                log("unrecognised frame kind \(rawKind); exiting")
                break
            }
            DispatchQueue.main.async {
                shim.handle(kind: kind, streamId: streamId, payload: payload)
            }
        }

        // Go closed stdin, which is the documented shutdown signal.
        DispatchQueue.main.async { exit(0) }
    }
    thread.stackSize = 512 * 1024
    thread.start()
}

// MARK: - main

let shim = BluetoothShim()
shim.start()
startReadingCommands(shim: shim)
// CoreBluetooth delivers callbacks on the main queue and the L2CAP streams are scheduled on the
// main run loop, so the process's job from here is to run that loop.
RunLoop.main.run()
