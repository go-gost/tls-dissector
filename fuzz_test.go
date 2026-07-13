package dissector

import (
	"bytes"
	"testing"
)

// FuzzParseClientHello parses a TLS ClientHello record. This is invoked by the
// SNI sniffer on EVERY inbound TLS connection BEFORE any policy check, so a
// panic is a DoS on the sniffing listener. Seeds are built with the library's
// own message helpers (valid ClientHello, minimal, non-handshake record,
// truncated) and the fuzzer mutates the raw record bytes — including the
// extension type-assertion paths that are the main crash surface.
func FuzzParseClientHello(f *testing.F) {
	msg := makeClientHelloMsg()
	if body, err := msg.Encode(); err == nil {
		f.Add(makeRecordBytes(Handshake, 0x0303, body))
	}
	minMsg := &ClientHelloMsg{Version: 0x0303, Random: Random{Time: 0}}
	if body, err := minMsg.Encode(); err == nil {
		f.Add(makeRecordBytes(Handshake, 0x0303, body))
	}
	f.Add(makeRecordBytes(AppData, 0x0303, []byte("hello"))) // non-handshake
	f.Add([]byte{})                                           // empty
	f.Add([]byte{Handshake, 0x03, 0x03, 0x00, 0x05})          // truncated payload
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseClientHello(bytes.NewReader(b))
	})
}

// FuzzParseServerHello parses a TLS ServerHello record (or an encrypted-alert
// record, which is a valid path). Input is attacker-controlled on the
// client-facing side of a MITM/sniffing proxy.
func FuzzParseServerHello(f *testing.F) {
	msg := makeServerHelloMsg()
	if body, err := msg.Encode(); err == nil {
		f.Add(makeRecordBytes(Handshake, 0x0303, body))
	}
	f.Add(makeRecordBytes(EncryptedAlert, 0x0303, []byte{0x02})) // alert path
	f.Add([]byte{})                                              // empty
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseServerHello(bytes.NewReader(b))
	})
}
