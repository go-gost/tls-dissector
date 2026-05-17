package dissector

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func wrapInRecord(contentType uint8, payload []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(contentType)
	binary.Write(buf, binary.BigEndian, Version(0x0303))
	binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)
	return buf.Bytes()
}

func TestParseClientHello(t *testing.T) {
	msg := makeClientHelloMsg()
	body, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	record := wrapInRecord(Handshake, body)
	info, err := ParseClientHello(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}

	if info.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "example.com")
	}
	if !reflect.DeepEqual(info.SupportedVersions, []uint16{0x0304, 0x0303}) {
		t.Errorf("SupportedVersions = %v, want [0304 0303]", info.SupportedVersions)
	}
	if !reflect.DeepEqual(info.SupportedProtos, []string{"h2", "http/1.1"}) {
		t.Errorf("SupportedProtos = %v, want [h2 http/1.1]", info.SupportedProtos)
	}
	if !bytes.Equal(info.SessionID, msg.SessionID) {
		t.Errorf("SessionID = %v, want %v", info.SessionID, msg.SessionID)
	}
	if !reflect.DeepEqual(info.CipherSuites, msg.CipherSuites) {
		t.Errorf("CipherSuites = %v, want %v", info.CipherSuites, msg.CipherSuites)
	}
	if !reflect.DeepEqual(info.CompressionMethods, msg.CompressionMethods) {
		t.Errorf("CompressionMethods = %v, want %v", info.CompressionMethods, msg.CompressionMethods)
	}
}

func TestParseClientHelloMinimal(t *testing.T) {
	msg := &ClientHelloMsg{
		Version:            0x0303,
		Random:             Random{Time: 0},
		SessionID:          nil,
		CipherSuites:       nil,
		CompressionMethods: nil,
		Extensions:         nil,
	}
	body, _ := msg.Encode()
	record := wrapInRecord(Handshake, body)

	info, err := ParseClientHello(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	if info.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", info.ServerName)
	}
	if len(info.SupportedVersions) != 0 {
		t.Errorf("SupportedVersions = %v, want empty", info.SupportedVersions)
	}
	if len(info.SupportedProtos) != 0 {
		t.Errorf("SupportedProtos = %v, want empty", info.SupportedProtos)
	}
}

func TestParseClientHelloBadRecord(t *testing.T) {
	record := wrapInRecord(AppData, []byte("hello"))
	_, err := ParseClientHello(bytes.NewReader(record))
	if err == nil {
		t.Fatal("expected error for non-handshake record")
	}
	if !strings.Contains(err.Error(), "bad type") {
		t.Errorf("error = %q, want containing 'bad type'", err.Error())
	}
}

func TestParseClientHelloTruncated(t *testing.T) {
	_, err := ParseClientHello(bytes.NewReader([]byte{}))
	if err == nil {
		t.Fatal("expected error for empty reader")
	}
}

func TestParseServerHello(t *testing.T) {
	msg := makeServerHelloMsg()
	body, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	record := wrapInRecord(Handshake, body)
	info, err := ParseServerHello(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}

	if info.CipherSuite != 0xC02B {
		t.Errorf("CipherSuite = %#x, want %#x", info.CipherSuite, 0xC02B)
	}
	if info.CompressionMethod != 0x00 {
		t.Errorf("CompressionMethod = %d, want 0", info.CompressionMethod)
	}
	if info.Proto != "h2" {
		t.Errorf("Proto = %q, want %q", info.Proto, "h2")
	}
	if info.Version != 0x0304 {
		t.Errorf("Version = %#x, want %#x (from supported_versions)", info.Version, 0x0304)
	}
	if !bytes.Equal(info.SessionID, msg.SessionID) {
		t.Errorf("SessionID = %v, want %v", info.SessionID, msg.SessionID)
	}
}

func TestParseServerHelloVersionFromMsg(t *testing.T) {
	msg := &ServerHelloMsg{
		Version:           0x0301,
		Random:            Random{Time: 0},
		SessionID:         nil,
		CipherSuite:       0x0005,
		CompressionMethod: 0x00,
		Extensions:        nil,
	}
	body, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	record := wrapInRecord(Handshake, body)
	info, err := ParseServerHello(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}

	if info.Version != 0x0301 {
		t.Errorf("Version = %#x, want %#x (from msg.Version, no supported_versions ext)", info.Version, 0x0301)
	}
}

func TestParseServerHelloAlert(t *testing.T) {
	alert := &AlertMsg{Level: 2, Description: 40}
	body, err := alert.Encode()
	if err != nil {
		t.Fatalf("Alert Encode error: %v", err)
	}

	record := wrapInRecord(EncryptedAlert, body)
	_, err = ParseServerHello(bytes.NewReader(record))
	if err == nil {
		t.Fatal("expected ErrAlert")
	}
	if !strings.Contains(err.Error(), "alert") {
		t.Errorf("error = %q, want containing 'alert'", err.Error())
	}
}

func TestParseServerHelloBadRecord(t *testing.T) {
	record := wrapInRecord(AppData, []byte("data"))
	_, err := ParseServerHello(bytes.NewReader(record))
	if err == nil {
		t.Fatal("expected error for non-handshake record")
	}
	if !strings.Contains(err.Error(), "bad type") {
		t.Errorf("error = %q, want containing 'bad type'", err.Error())
	}
}

func TestParseServerHelloTruncated(t *testing.T) {
	_, err := ParseServerHello(bytes.NewReader([]byte{}))
	if err == nil {
		t.Fatal("expected error for empty reader")
	}
}
