package dissector

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

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
		{40, "handshake failure"},
		{70, "protocol version"},
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
