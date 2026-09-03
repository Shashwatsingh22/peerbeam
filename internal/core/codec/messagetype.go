package codec

import "fmt"

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

// String names the message type for reports and event log entries.
//
// Req 10.6 permits the message type to be logged - it is one of the three things a MessageTrace may
// carry - so a readable name is useful rather than a leak. An unrecognised code renders as its number,
// since Req 8.8 keeps such a frame rather than rejecting it and a report still has to say what arrived.
func (t MessageType) String() string {
	switch t {
	case MsgKeyExchangeInit:
		return "KEY_EXCHANGE_INIT"
	case MsgKeyExchangeResponse:
		return "KEY_EXCHANGE_RESPONSE"
	case MsgText:
		return "TEXT"
	case MsgClipboard:
		return "CLIPBOARD"
	case MsgTransferOffer:
		return "TRANSFER_OFFER"
	case MsgTransferOfferReply:
		return "TRANSFER_OFFER_REPLY"
	case MsgChunk:
		return "CHUNK"
	case MsgChunkAck:
		return "CHUNK_ACK"
	case MsgDeliveryAck:
		return "DELIVERY_ACK"
	case MsgError:
		return "ERROR"
	case MsgKeepalive:
		return "KEEPALIVE"
	case MsgKeepaliveAck:
		return "KEEPALIVE_ACK"
	case MsgTransferCancel:
		return "TRANSFER_CANCEL"
	default:
		return fmt.Sprintf("MessageType(%d)", uint8(t))
	}
}
