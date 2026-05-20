package dissector

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Shared test helpers for all test files in this package.

type failingWriter struct{}

func (f failingWriter) Write([]byte) (int, error) { return 0, errors.New("write error") }

type errorExtension struct{}

func (e *errorExtension) Type() uint16           { return 0xFFFF }
func (e *errorExtension) Encode() ([]byte, error) { return nil, errors.New("encode error") }
func (e *errorExtension) Decode(b []byte) error   { return nil }

func makeRecordBytes(contentType uint8, version Version, payload []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(contentType)
	binary.Write(buf, binary.BigEndian, version)
	binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)
	return buf.Bytes()
}

func makeClientHelloMsg() *ClientHelloMsg {
	return &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 1234567890, Opaque: [28]byte{0xaa, 0xbb, 0xcc}},
		SessionID:          []byte{0x01, 0x02, 0x03},
		CipherSuites:       []uint16{0xC02B, 0xC02F, 0xCCA8},
		CompressionMethods: []uint8{0x00},
		Extensions: []Extension{
			&ServerNameExtension{NameType: 0, Name: "example.com"},
			&SupportedVersionsExtension{Versions: []uint16{0x0304, 0x0303}},
			&ALPNExtension{Protos: []string{"h2", "http/1.1"}},
		},
	}
}

func makeServerHelloMsg() *ServerHelloMsg {
	return &ServerHelloMsg{
		Version:           0x0303,
		Random:            Random{Time: 987654321, Opaque: [28]byte{0xdd, 0xee}},
		SessionID:         []byte{0xaa, 0xbb},
		CipherSuite:       0xC02B,
		CompressionMethod: 0x00,
		Extensions: []Extension{
			&SupportedVersionsExtension{Versions: []uint16{0x0304}, Server: true},
			&ALPNExtension{Protos: []string{"h2"}},
		},
	}
}

func copyOf(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
