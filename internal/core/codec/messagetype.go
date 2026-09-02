package codec

// MessageType enumerates the known message types. Anything else is an
// unrecognised code (Req 8.8). The wire codes are fixed, so they are written
// out explicitly rather than derived with iota.
type MessageType uint8

const (
	MsgKeyExchangeInit     MessageType = 1
	MsgKeyExchangeResponse MessageType = 2
	MsgText                MessageType = 3
	MsgClipboard           MessageType = 4
	MsgTransferOffer       MessageType = 5
	MsgTransferOfferReply  MessageType = 6
	MsgChunk               MessageType = 7
	MsgChunkAck            MessageType = 8
	MsgDeliveryAck         MessageType = 9
	MsgError               MessageType = 10
	MsgKeepalive           MessageType = 11
	MsgKeepaliveAck        MessageType = 12
	MsgTransferCancel      MessageType = 13
)

var knownTypes = map[uint8]MessageType{
	1: MsgKeyExchangeInit, 2: MsgKeyExchangeResponse, 3: MsgText, 4: MsgClipboard,
	5: MsgTransferOffer, 6: MsgTransferOfferReply, 7: MsgChunk, 8: MsgChunkAck,
	9: MsgDeliveryAck, 10: MsgError, 11: MsgKeepalive, 12: MsgKeepaliveAck,
	13: MsgTransferCancel,
}

// MessageTypeFromCode reports the known type for a code, or ok == false (Req 8.8).
func MessageTypeFromCode(code uint8) (MessageType, bool) {
	mt, ok := knownTypes[code]
	return mt, ok
}
