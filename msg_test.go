package dissector

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestClientHelloMsgRoundTrip(t *testing.T) {
	original := makeClientHelloMsg()

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded := &ClientHelloMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("Version = %#x, want %#x", decoded.Version, original.Version)
	}
	if decoded.Random.Time != original.Random.Time {
		t.Errorf("Random.Time = %d, want %d", decoded.Random.Time, original.Random.Time)
	}
	if decoded.Random.Opaque != original.Random.Opaque {
		t.Errorf("Random.Opaque mismatch")
	}
	if !bytes.Equal(decoded.SessionID, original.SessionID) {
		t.Errorf("SessionID = %v, want %v", decoded.SessionID, original.SessionID)
	}
	if !reflect.DeepEqual(decoded.CipherSuites, original.CipherSuites) {
		t.Errorf("CipherSuites = %v, want %v", decoded.CipherSuites, original.CipherSuites)
	}
	if !reflect.DeepEqual(decoded.CompressionMethods, original.CompressionMethods) {
		t.Errorf("CompressionMethods = %v, want %v", decoded.CompressionMethods, original.CompressionMethods)
	}
	if len(decoded.Extensions) != len(original.Extensions) {
		t.Fatalf("extensions count = %d, want %d", len(decoded.Extensions), len(original.Extensions))
	}
	for i, ext := range decoded.Extensions {
		if ext.Type() != original.Extensions[i].Type() {
			t.Errorf("extension[%d] type = %#x, want %#x", i, ext.Type(), original.Extensions[i].Type())
		}
	}
}

func TestClientHelloMsgMinimal(t *testing.T) {
	msg := &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 0},
		SessionID:          nil,
		CipherSuites:       nil,
		CompressionMethods: nil,
		Extensions:         nil,
	}
	encoded, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded := &ClientHelloMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if decoded.Version != msg.Version {
		t.Errorf("Version = %#x, want %#x", decoded.Version, msg.Version)
	}
	if len(decoded.SessionID) != 0 {
		t.Errorf("SessionID should be empty, got %v", decoded.SessionID)
	}
	if len(decoded.CipherSuites) != 0 {
		t.Errorf("CipherSuites should be empty, got %v", decoded.CipherSuites)
	}
	if len(decoded.CompressionMethods) != 0 {
		t.Errorf("CompressionMethods should be empty, got %v", decoded.CompressionMethods)
	}
	if len(decoded.Extensions) != 0 {
		t.Errorf("Extensions should be empty, got %d", len(decoded.Extensions))
	}
}

func TestClientHelloMsgDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "wrong type",
			data:    []byte{ServerHello, 0, 0, 34, 0x03, 0x03},
			wantErr: "bad type",
		},
		{
			name:    "too short length",
			data:    []byte{ClientHello, 0, 0, 10, 0x03},
			wantErr: "at least 34 bytes",
		},
		{
			name:    "truncated payload",
			data:    []byte{ClientHello, 0, 0, 36},
			wantErr: "EOF",
		},
		{
			name: "bad version too low",
			data: append(
				[]byte{ClientHello, 0, 0, 36},
				append([]byte{0x02, 0x00}, make([]byte, 34)...)...,
			),
			wantErr: "bad version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &ClientHelloMsg{}
			err := msg.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestServerHelloMsgRoundTrip(t *testing.T) {
	original := makeServerHelloMsg()

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded := &ServerHelloMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("Version = %#x, want %#x", decoded.Version, original.Version)
	}
	if decoded.Random.Time != original.Random.Time {
		t.Errorf("Random.Time = %d, want %d", decoded.Random.Time, original.Random.Time)
	}
	if decoded.Random.Opaque != original.Random.Opaque {
		t.Errorf("Random.Opaque mismatch")
	}
	if !bytes.Equal(decoded.SessionID, original.SessionID) {
		t.Errorf("SessionID = %v, want %v", decoded.SessionID, original.SessionID)
	}
	if decoded.CipherSuite != original.CipherSuite {
		t.Errorf("CipherSuite = %#x, want %#x", decoded.CipherSuite, original.CipherSuite)
	}
	if decoded.CompressionMethod != original.CompressionMethod {
		t.Errorf("CompressionMethod = %d, want %d", decoded.CompressionMethod, original.CompressionMethod)
	}
	if len(decoded.Extensions) != len(original.Extensions) {
		t.Fatalf("extensions count = %d, want %d", len(decoded.Extensions), len(original.Extensions))
	}
}

func TestServerHelloMsgMinimal(t *testing.T) {
	msg := &ServerHelloMsg{
		Version:           0x0303,
		Random:            Random{Time: 0},
		SessionID:         nil,
		CipherSuite:       0xC02B,
		CompressionMethod: 0x00,
		Extensions:        nil,
	}
	encoded, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded := &ServerHelloMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if decoded.Version != msg.Version {
		t.Errorf("Version = %#x, want %#x", decoded.Version, msg.Version)
	}
	if decoded.CipherSuite != msg.CipherSuite {
		t.Errorf("CipherSuite = %#x, want %#x", decoded.CipherSuite, msg.CipherSuite)
	}
	if decoded.CompressionMethod != msg.CompressionMethod {
		t.Errorf("CompressionMethod = %d, want %d", decoded.CompressionMethod, msg.CompressionMethod)
	}
}

func TestServerHelloMsgDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "wrong type",
			data:    []byte{ClientHello, 0, 0, 34, 0x03, 0x03},
			wantErr: "bad type",
		},
		{
			name:    "too short length",
			data:    []byte{ServerHello, 0, 0, 10, 0x03},
			wantErr: "at least 34 bytes",
		},
		{
			name:    "truncated payload",
			data:    []byte{ServerHello, 0, 0, 50},
			wantErr: "EOF",
		},
		{
			name: "bad version too low",
			data: append(
				[]byte{ServerHello, 0, 0, 34},
				append([]byte{0x02, 0x00}, make([]byte, 32)...)...,
			),
			wantErr: "bad version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &ServerHelloMsg{}
			err := msg.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestAlertMsgDecode(t *testing.T) {
	msg := &AlertMsg{}
	err := msg.Decode([]byte{0x02, 0x28})
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if msg.Level != 2 {
		t.Errorf("Level = %d, want 2", msg.Level)
	}
	if msg.Description != 40 {
		t.Errorf("Description = %d, want 40", msg.Description)
	}
	if s := msg.String(); s != "fatal: handshake failure" {
		t.Errorf("String = %q, want %q", s, "fatal: handshake failure")
	}
}

func TestAlertMsgDecodeTruncated(t *testing.T) {
	msg := &AlertMsg{}
	err := msg.Decode([]byte{0x02})
	if err == nil {
		t.Fatal("expected error for truncated alert")
	}
}

func TestAlertMsgRoundTrip(t *testing.T) {
	original := &AlertMsg{Level: 1, Description: 0}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded := &AlertMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.Level != original.Level || decoded.Description != original.Description {
		t.Errorf("got Level=%d Desc=%d, want Level=%d Desc=%d",
			decoded.Level, decoded.Description, original.Level, original.Description)
	}
}

func TestAlertLevelString(t *testing.T) {
	tests := []struct {
		level AlertLevel
		want  string
	}{
		{1, "warning"},
		{2, "fatal"},
		{0, "unknown level: 0"},
		{3, "unknown level: 3"},
	}
	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("AlertLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestAlertDescriptionString(t *testing.T) {
	tests := []struct {
		desc AlertDescription
		want string
	}{
		{0, "close notify"},
		{10, "unexpected message"},
		{20, "bad record mac"},
		{21, "decryption failed RESERVED"},
		{22, "record overflow"},
		{30, "decompression failure"},
		{40, "handshake failure"},
		{41, "no certificate RESERVED"},
		{42, "bad certificate"},
		{43, "unsupported certificate"},
		{44, "certificate revoked"},
		{45, "certificate expired"},
		{46, "certificate unknown"},
		{47, "illegal parameter"},
		{48, "unknown ca"},
		{49, "access denied"},
		{50, "decode error"},
		{51, "decrypt error"},
		{60, "export restriction RESERVED"},
		{70, "protocol version"},
		{71, "insufficient security"},
		{80, "internal error"},
		{86, "inappropriate fallback"},
		{90, "user canceled"},
		{100, "no renegotiation"},
		{110, "unsupported extension"},
		{111, "certificate unobtainable"},
		{112, "unrecognized name"},
		{113, "bad certificate status response"},
		{114, "bad certificate hash value"},
		{115, "unknown PSK identity"},
		{116, "certificate required"},
		{120, "no application protocol"},
		{255, "unknown desc: 255"},
	}
	for _, tt := range tests {
		got := tt.desc.String()
		if got != tt.want {
			t.Errorf("AlertDescription(%d).String() = %q, want %q", tt.desc, got, tt.want)
		}
	}
}

// Test decode errors for readSession, readCipherSuites, readCompressionMethods, readExtensions
func TestClientHelloMsgDecodeMalformed(t *testing.T) {
	valid := &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 0},
		SessionID:          []byte{0xAA},
		CipherSuites:       []uint16{0xC02B},
		CompressionMethods: []uint8{0x00},
	}
	validEncoded, err := valid.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr string
	}{
		{
			name: "session length claims too much",
			mutate: func(b []byte) []byte {
				b[38] = 100 // session len
				return b
			},
			wantErr: "malformed data for session",
		},
		{
			name: "cipher suites length claims too much",
			mutate: func(b []byte) []byte {
				b[40] = 0x01 // cipher suites len = 256
				b[41] = 0x00
				return b
			},
			wantErr: "malformed data for cipher suites",
		},
		{
			name: "compression methods length claims too much",
			mutate: func(b []byte) []byte {
				b[44] = 100 // comp methods len
				return b
			},
			wantErr: "malformed data for compression methods",
		},
		{
			name: "extensions length claims too much",
			mutate: func(b []byte) []byte {
				b[46] = 0xFF
				b[47] = 0xFF
				return b
			},
			wantErr: "malformed data for extensions",
		},
		{
			name: "payload too short for session byte",
			mutate: func(b []byte) []byte {
				// Set payload length to exactly 34 (version + random only)
				data := make([]byte, 4+34)
				copy(data, b[:4+34])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 34
				return data
			},
			wantErr: "data too short for session",
		},
		{
			name: "truncated in middle of session data",
			mutate: func(b []byte) []byte {
				// Payload includes version+random+session_len(1) but no session data
				data := make([]byte, 4+35)
				copy(data, b[:4+35])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 35
				return data
			},
			wantErr: "malformed data for session",
		},
		{
			name: "truncated before cipher suites header",
			mutate: func(b []byte) []byte {
				// Payload includes version+random+session, but truncated before cipher suites length
				// 34 + session(1+1=2) = 36, then cipher needs 2 bytes. Cut at 37.
				data := make([]byte, 4+37)
				copy(data, b[:4+37])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 37
				return data
			},
			wantErr: "data too short for cipher suites",
		},
		{
			name: "truncated before compression header",
			mutate: func(b []byte) []byte {
				// Payload needs: version+random(34) + session(2) + cipher(4) = 40 just enough
				// 4+40 = 44. At 40 bytes payload, readCompressionMethods gets empty input.
				data := make([]byte, 4+40)
				copy(data, b[:4+40])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 40
				return data
			},
			wantErr: "data too short for compression methods",
		},
		{
			name: "truncated before extensions header",
			mutate: func(b []byte) []byte {
				// Payload needs: version+random(34) + session(2) + cipher(4) + comp(2) = 42
				data := make([]byte, 4+43)
				copy(data, b[:4+42])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 43
				return data
			},
			wantErr: "data too short for extensions",
		},
		{
			name: "truncated mid-extension",
			mutate: func(b []byte) []byte {
				full := &ClientHelloMsg{
					Version:            0x0303,
					Random:             Random{Time: 0},
					SessionID:          []byte{0xAA},
					CipherSuites:       []uint16{0xC02B},
					CompressionMethods: []uint8{0x00},
					Extensions: []Extension{
						&ServerNameExtension{NameType: 0, Name: "example.com"},
						&ALPNExtension{Protos: []string{"h2", "http/1.1"}},
					},
				}
				fb, _ := full.Encode()
				return fb[:len(fb)-5] // truncate inside second extension
			},
			wantErr: "EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &ClientHelloMsg{}
			err := msg.Decode(tt.mutate(copyOf(validEncoded)))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestClientHelloMsgEncodeError(t *testing.T) {
	msg := &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 0},
		Extensions:         []Extension{&errorExtension{}},
		CipherSuites:       []uint16{0xC02B},
		CompressionMethods: []uint8{0x00},
	}
	_, err := msg.Encode()
	if err == nil {
		t.Fatal("expected error from extension encode, got nil")
	}
}

func TestServerHelloMsgEncodeError(t *testing.T) {
	msg := &ServerHelloMsg{
		Version:           0x0303,
		Random:            Random{Time: 0},
		CipherSuite:       0xC02B,
		CompressionMethod: 0x00,
		Extensions:        []Extension{&errorExtension{}},
	}
	_, err := msg.Encode()
	if err == nil {
		t.Fatal("expected error from extension encode, got nil")
	}
}

func TestClientHelloMsgWriteToError(t *testing.T) {
	msg := makeClientHelloMsg()
	_, err := msg.WriteTo(failingWriter{})
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestServerHelloMsgWriteToError(t *testing.T) {
	msg := makeServerHelloMsg()
	_, err := msg.WriteTo(failingWriter{})
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestClientHelloMsgDecodeBadVersion(t *testing.T) {
	msg := &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 0},
		SessionID:          []byte{0xAA},
		CipherSuites:       []uint16{0xC02B},
		CompressionMethods: []uint8{0x00},
	}
	encoded, _ := msg.Encode()
	// Corrupt the version bytes in the payload (offset 4+2=6: msg type + 3 len + handshake type + 3 len)
	// Actually: record header is stripped. The encoded data from Encode() is just the handshake message body.
	// Body: 1(type) + 3(len) + 2(version) + 32(random) + ...
	// Version is at offset 4 in the body
	encoded[4] = 0x04 // make version 0x04xx which is > TLS 1.3
	encoded[5] = 0x00

	decoded := &ClientHelloMsg{}
	err := decoded.Decode(encoded)
	if err == nil {
		t.Fatal("expected bad version error")
	}
	if !strings.Contains(err.Error(), "bad version") {
		t.Errorf("error = %q, want containing 'bad version'", err.Error())
	}
}

func TestServerHelloMsgDecodeBadVersion(t *testing.T) {
	msg := &ServerHelloMsg{
		Version:           0x0303,
		Random:            Random{Time: 0},
		CipherSuite:       0xC02B,
		CompressionMethod: 0x00,
	}
	encoded, _ := msg.Encode()
	encoded[4] = 0x04
	encoded[5] = 0x00

	decoded := &ServerHelloMsg{}
	err := decoded.Decode(encoded)
	if err == nil {
		t.Fatal("expected bad version error")
	}
	if !strings.Contains(err.Error(), "bad version") {
		t.Errorf("error = %q, want containing 'bad version'", err.Error())
	}
}

func TestServerHelloMsgDecodeMalformed(t *testing.T) {
	valid := &ServerHelloMsg{
		Version:           0x0303,
		Random:            Random{Time: 0},
		SessionID:         []byte{0xAA},
		CipherSuite:       0xC02B,
		CompressionMethod: 0x00,
	}
	validEncoded, _ := valid.Encode()

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr string
	}{
		{
			name: "server session malformed",
			mutate: func(b []byte) []byte {
				b[38] = 100
				return b
			},
			wantErr: "malformed data for session",
		},
		{
			name: "server extensions malformed",
			mutate: func(b []byte) []byte {
				// After session(1+1) + cipher(2) + compression(1) = 5 bytes from offset 38
				// cipher suite and compression stay at their offsets
				// So: session len=1 at [38], session=[39], cipher=[40-41], comp=[42]
				// extensions len at [43-44]
				// But wait: session is 1 byte so 1+1=2 bytes; cipher=2 bytes; comp=1 byte
				// Offset: 38(session len) + 1+1 + 2 + 1 = 43 (extensions len)
				b[43] = 0xFF
				b[44] = 0xFF
				return b
			},
			wantErr: "malformed data for extensions",
		},
		{
			name: "server too short for session",
			mutate: func(b []byte) []byte {
				data := make([]byte, 4+34)
				copy(data, b[:4+34])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 34
				return data
			},
			wantErr: "data too short for session",
		},
		{
			name: "server too short for extensions",
			mutate: func(b []byte) []byte {
				// 34 + session(2) + cipher(2) + comp(1) = 39, cut at 39 to leave 0 bytes for extensions
				data := make([]byte, 4+40)
				copy(data, b[:4+39])
				binary.BigEndian.PutUint16(data[1:3], 0)
				data[3] = 40
				return data
			},
			wantErr: "data too short for extensions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &ServerHelloMsg{}
			err := msg.Decode(tt.mutate(copyOf(validEncoded)))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestClientHelloMsgReadFromErrors(t *testing.T) {
	msg := &ClientHelloMsg{}
	_, err := msg.ReadFrom(bytes.NewReader([]byte{ClientHello, 0x00}))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "EOF") {
		t.Errorf("error = %q, want containing 'EOF'", err.Error())
	}
}

func TestServerHelloMsgReadFromErrors(t *testing.T) {
	msg := &ServerHelloMsg{}
	_, err := msg.ReadFrom(bytes.NewReader([]byte{ServerHello, 0x00}))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "EOF") {
		t.Errorf("error = %q, want containing 'EOF'", err.Error())
	}
}

// Regression: BUG 1 — ServerHello with short payload must not panic
func TestServerHelloReadFrom_ShortPayload(t *testing.T) {
	tests := []struct {
		name    string
		bodyLen int
		wantErr string
	}{
		{name: "payload 35 too short", bodyLen: 35, wantErr: "cipher suite"},
		{name: "payload 36 too short", bodyLen: 36, wantErr: "cipher suite"},
		{name: "payload 37 too short", bodyLen: 37, wantErr: "cipher suite"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := make([]byte, 4+tt.bodyLen)
			body[0] = ServerHello
			binary.BigEndian.PutUint16(body[4:6], 0x0303)
			body[3] = byte(tt.bodyLen)
			msg := &ServerHelloMsg{}
			err := msg.Decode(body)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// Regression: BUG 5 — TLS 1.2 ClientHello/ServerHello without extensions must succeed
func TestClientHelloWithoutExtensions(t *testing.T) {
	msg := &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 0},
		SessionID:          []byte{0xAA},
		CipherSuites:       []uint16{0xC02B},
		CompressionMethods: []uint8{0x00},
		Extensions:         nil,
	}
	encoded, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	decoded := &ClientHelloMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if len(decoded.Extensions) != 0 {
		t.Errorf("Extensions = %d, want 0", len(decoded.Extensions))
	}
}

func TestServerHelloWithoutExtensions(t *testing.T) {
	msg := &ServerHelloMsg{
		Version:           0x0303,
		Random:            Random{Time: 0},
		SessionID:         []byte{0xAA},
		CipherSuite:       0xC02B,
		CompressionMethod: 0x00,
		Extensions:        nil,
	}
	encoded, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	decoded := &ServerHelloMsg{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if len(decoded.Extensions) != 0 {
		t.Errorf("Extensions = %d, want 0", len(decoded.Extensions))
	}
}
