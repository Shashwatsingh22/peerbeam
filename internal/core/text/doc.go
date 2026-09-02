// Package text holds the text message rules: size validation against the
// 1..65,536 UTF-8 byte range, strict UTF-8 decoding, and the inbound
// disposition that always acknowledges but displays only complete, valid
// messages.
//
// Pure logic only. This package must not import net, os, or any socket API.
package text
