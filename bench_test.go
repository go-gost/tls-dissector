package dissector

import (
	"bytes"
	"testing"
)

func BenchmarkParseClientHello(b *testing.B) {
	msg := makeClientHelloMsg()
	body, err := msg.Encode()
	if err != nil {
		b.Fatalf("Encode: %v", err)
	}
	record := makeRecordBytes(Handshake, 0x0303, body)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(record)
		_, err := ParseClientHello(r)
		if err != nil {
			b.Fatalf("ParseClientHello: %v", err)
		}
	}
}

func BenchmarkParseServerHello(b *testing.B) {
	msg := makeServerHelloMsg()
	body, err := msg.Encode()
	if err != nil {
		b.Fatalf("Encode: %v", err)
	}
	record := makeRecordBytes(Handshake, 0x0303, body)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(record)
		_, err := ParseServerHello(r)
		if err != nil {
			b.Fatalf("ParseServerHello: %v", err)
		}
	}
}

func BenchmarkReadRecord(b *testing.B) {
	msg := makeClientHelloMsg()
	body, _ := msg.Encode()
	record := makeRecordBytes(Handshake, 0x0303, body)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(record)
		_, err := ReadRecord(r)
		if err != nil {
			b.Fatalf("ReadRecord: %v", err)
		}
	}
}

func BenchmarkClientHelloMsgDecode(b *testing.B) {
	msg := makeClientHelloMsg()
	body, err := msg.Encode()
	if err != nil {
		b.Fatalf("Encode: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := &ClientHelloMsg{}
		if err := m.Decode(body); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

func BenchmarkServerHelloMsgDecode(b *testing.B) {
	msg := makeServerHelloMsg()
	body, err := msg.Encode()
	if err != nil {
		b.Fatalf("Encode: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m := &ServerHelloMsg{}
		if err := m.Decode(body); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

func BenchmarkClientHelloMsgEncode(b *testing.B) {
	msg := makeClientHelloMsg()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := msg.Encode()
		if err != nil {
			b.Fatalf("Encode: %v", err)
		}
	}
}

func BenchmarkServerHelloMsgEncode(b *testing.B) {
	msg := makeServerHelloMsg()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := msg.Encode()
		if err != nil {
			b.Fatalf("Encode: %v", err)
		}
	}
}

func BenchmarkReadExtensions(b *testing.B) {
	msg := makeClientHelloMsg()
	body, _ := msg.Encode()

	// Decode just far enough to get the raw extension bytes.
	m := &ClientHelloMsg{}
	m.Decode(body)
	raw := encodeExtensions(m.Extensions)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := readExtensions(raw)
		if err != nil {
			b.Fatalf("readExtensions: %v", err)
		}
	}
}

func BenchmarkNewExtension(b *testing.B) {
	ext := &ServerNameExtension{NameType: 0, Name: "example.com"}
	data, _ := ext.Encode()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := NewExtension(ExtServerName, data)
		if err != nil {
			b.Fatalf("NewExtension: %v", err)
		}
	}
}

// encodeExtensions serializes a slice of extensions into raw bytes
// (type + length + data for each), matching the wire format that
// readExtensions expects (without the outer 2-byte total length).
func encodeExtensions(exts []Extension) []byte {
	buf := new(bytes.Buffer)
	for _, ext := range exts {
		data, _ := ext.Encode()
		buf.Write([]byte{byte(ext.Type() >> 8), byte(ext.Type())})
		buf.Write([]byte{byte(len(data) >> 8), byte(len(data))})
		buf.Write(data)
	}
	return buf.Bytes()
}
