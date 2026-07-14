package dissector

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func extRoundTrip(t *testing.T, name string, original Extension) {
	t.Helper()
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("%s Encode error: %v", name, err)
	}

	decoded, err := NewExtension(original.Type(), encoded)
	if err != nil {
		t.Fatalf("%s NewExtension error: %v", name, err)
	}

	if decoded.Type() != original.Type() {
		t.Errorf("%s type = %#x, want %#x", name, decoded.Type(), original.Type())
	}

	switch orig := original.(type) {
	case *ServerNameExtension:
		d, ok := decoded.(*ServerNameExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if d.NameType != orig.NameType || d.Name != orig.Name {
			t.Errorf("%s got %+v, want %+v", name, d, orig)
		}
	case *SupportedGroupsExtension:
		d, ok := decoded.(*SupportedGroupsExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Groups, orig.Groups) {
			t.Errorf("%s Groups = %v, want %v", name, d.Groups, orig.Groups)
		}
	case *ECPointFormatsExtension:
		d, ok := decoded.(*ECPointFormatsExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Formats, orig.Formats) {
			t.Errorf("%s Formats = %v, want %v", name, d.Formats, orig.Formats)
		}
	case *SignatureAlgorithmsExtension:
		d, ok := decoded.(*SignatureAlgorithmsExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Algorithms, orig.Algorithms) {
			t.Errorf("%s Algorithms = %v, want %v", name, d.Algorithms, orig.Algorithms)
		}
	case *ALPNExtension:
		d, ok := decoded.(*ALPNExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Protos, orig.Protos) {
			t.Errorf("%s Protos = %v, want %v", name, d.Protos, orig.Protos)
		}
	case *EncryptThenMacExtension:
		_, ok := decoded.(*EncryptThenMacExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
	case *ExtendedMasterSecretExtension:
		_, ok := decoded.(*ExtendedMasterSecretExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
	case *SessionTicketExtension:
		d, ok := decoded.(*SessionTicketExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !bytes.Equal(d.Data, orig.Data) {
			t.Errorf("%s Data = %v, want %v", name, d.Data, orig.Data)
		}
	case *SupportedVersionsExtension:
		d, ok := decoded.(*SupportedVersionsExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Versions, orig.Versions) {
			t.Errorf("%s Versions = %v, want %v", name, d.Versions, orig.Versions)
		}
		if d.Server != orig.Server {
			t.Errorf("%s Server = %v, want %v", name, d.Server, orig.Server)
		}
	case *RenegotiationInfoExtension:
		d, ok := decoded.(*RenegotiationInfoExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !bytes.Equal(d.Data, orig.Data) {
			t.Errorf("%s Data = %v, want %v", name, d.Data, orig.Data)
		}
	case *KeyShareExtension:
		d, ok := decoded.(*KeyShareExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if len(d.Entries) != len(orig.Entries) {
			t.Errorf("%s Entries count = %d, want %d", name, len(d.Entries), len(orig.Entries))
		}
		for i, e := range d.Entries {
			if i >= len(orig.Entries) {
				break
			}
			if e.Group != orig.Entries[i].Group {
				t.Errorf("%s Entry[%d].Group = %#x, want %#x", name, i, e.Group, orig.Entries[i].Group)
			}
			if !bytes.Equal(e.KeyExchange, orig.Entries[i].KeyExchange) {
				t.Errorf("%s Entry[%d].KeyExchange mismatch", name, i)
			}
		}
		if d.Server != orig.Server {
			t.Errorf("%s Server = %v, want %v", name, d.Server, orig.Server)
		}
	case *PskKeyExchangeModesExtension:
		d, ok := decoded.(*PskKeyExchangeModesExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Modes, orig.Modes) {
			t.Errorf("%s Modes = %v, want %v", name, d.Modes, orig.Modes)
		}
	case *PreSharedKeyExtension:
		d, ok := decoded.(*PreSharedKeyExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if len(d.Identities) != len(orig.Identities) {
			t.Errorf("%s Identities count = %d, want %d", name, len(d.Identities), len(orig.Identities))
		}
		for i, id := range d.Identities {
			if i >= len(orig.Identities) {
				break
			}
			if !bytes.Equal(id.Identity, orig.Identities[i].Identity) {
				t.Errorf("%s Identity[%d] mismatch", name, i)
			}
			if id.ObfuscatedTicketAge != orig.Identities[i].ObfuscatedTicketAge {
				t.Errorf("%s Identity[%d].Age = %d, want %d", name, i, id.ObfuscatedTicketAge, orig.Identities[i].ObfuscatedTicketAge)
			}
		}
		if len(d.Binders) != len(orig.Binders) {
			t.Errorf("%s Binders count = %d, want %d", name, len(d.Binders), len(orig.Binders))
		}
		for i, b := range d.Binders {
			if i >= len(orig.Binders) {
				break
			}
			if !bytes.Equal(b, orig.Binders[i]) {
				t.Errorf("%s Binder[%d] mismatch", name, i)
			}
		}
		if d.SelectedIdentity != orig.SelectedIdentity {
			t.Errorf("%s SelectedIdentity = %d, want %d", name, d.SelectedIdentity, orig.SelectedIdentity)
		}
		if d.Server != orig.Server {
			t.Errorf("%s Server = %v, want %v", name, d.Server, orig.Server)
		}
	case *SignatureAlgorithmsCertExtension:
		d, ok := decoded.(*SignatureAlgorithmsCertExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !reflect.DeepEqual(d.Algorithms, orig.Algorithms) {
			t.Errorf("%s Algorithms = %v, want %v", name, d.Algorithms, orig.Algorithms)
		}
	case *CookieExtension:
		d, ok := decoded.(*CookieExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if !bytes.Equal(d.Data, orig.Data) {
			t.Errorf("%s Data = %v, want %v", name, d.Data, orig.Data)
		}
	case *EarlyDataExtension:
		_, ok := decoded.(*EarlyDataExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
	case *unknownExtension:
		d, ok := decoded.(*unknownExtension)
		if !ok {
			t.Fatalf("%s wrong decoded type: %T", name, decoded)
		}
		if d.Type() != orig.Type() {
			t.Errorf("%s type = %#x, want %#x", name, d.Type(), orig.Type())
		}
		if !bytes.Equal(d.raw, orig.raw) {
			t.Errorf("%s raw = %v, want %v", name, d.raw, orig.raw)
		}
	}
}

func TestServerNameExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "server_name", &ServerNameExtension{NameType: 0, Name: "example.com"})
}

func TestServerNameExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"truncated name", []byte{0x00, 0x0a, 0x00, 0x00, 0x10}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &ServerNameExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSupportedGroupsExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "supported_groups", &SupportedGroupsExtension{
		Groups: []uint16{0x001D, 0x0017, 0x0018},
	})
}

func TestSupportedGroupsExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"odd length", []byte{0x00, 0x03, 0x00, 0x01}, "odd group list length"},
		{"truncated data", []byte{0x00, 0x04, 0x00}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &SupportedGroupsExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestECPointFormatsExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "ec_point_formats", &ECPointFormatsExtension{
		Formats: []uint8{0x00},
	})
}

func TestECPointFormatsExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{}, "short buffer"},
		{"truncated formats", []byte{0x03, 0x00}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &ECPointFormatsExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSignatureAlgorithmsExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "signature_algorithms", &SignatureAlgorithmsExtension{
		Algorithms: []uint16{0x0403, 0x0503, 0x0603},
	})
}

func TestSignatureAlgorithmsExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"truncated data", []byte{0x00, 0x06, 0x04, 0x03}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &SignatureAlgorithmsExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestALPNExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "alpn", &ALPNExtension{
		Protos: []string{"h2", "http/1.1"},
	})
}

func TestALPNExtensionEmpty(t *testing.T) {
	extRoundTrip(t, "alpn_empty", &ALPNExtension{Protos: nil})
}

func TestALPNExtensionSkipEmpty(t *testing.T) {
	ext := &ALPNExtension{Protos: []string{"h2", "", "http/1.1"}}
	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	decoded := &ALPNExtension{}
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if len(decoded.Protos) != 2 {
		t.Errorf("Protos count = %d, want 2 (empty skipped)", len(decoded.Protos))
	}
}

func TestALPNExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"truncated alpn list", []byte{0x00, 0x10, 0x02, 'h'}, "short buffer"},
		{"missing proto length", []byte{0x00, 0x01}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &ALPNExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEncryptThenMacExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "encrypt_then_mac", &EncryptThenMacExtension{Data: []byte{0x01}})
}

func TestEncryptThenMacExtensionEmpty(t *testing.T) {
	extRoundTrip(t, "encrypt_then_mac_empty", &EncryptThenMacExtension{})
}

func TestExtendedMasterSecretExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "extended_master_secret", &ExtendedMasterSecretExtension{Data: []byte{0x01}})
}

func TestExtendedMasterSecretExtensionEmpty(t *testing.T) {
	extRoundTrip(t, "extended_master_secret_empty", &ExtendedMasterSecretExtension{})
}

func TestSessionTicketExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "session_ticket", &SessionTicketExtension{
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	})
}

func TestSupportedVersionsExtensionClientHello(t *testing.T) {
	extRoundTrip(t, "supported_versions_ch", &SupportedVersionsExtension{
		Versions: []uint16{0x0304, 0x0303},
		Server:   false,
	})
}

func TestSupportedVersionsExtensionServerHello(t *testing.T) {
	extRoundTrip(t, "supported_versions_sh", &SupportedVersionsExtension{
		Versions: []uint16{0x0304},
		Server:   true,
	})
}

func TestSupportedVersionsExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"odd version list", []byte{0x03, 0x03, 0x04, 0x05}, "odd version list length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &SupportedVersionsExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestRenegotiationInfoExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "renegotiation_info", &RenegotiationInfoExtension{
		Data: []byte{0x00},
	})
}

func TestRenegotiationInfoExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{}, "short buffer"},
		{"truncated data", []byte{0x03, 0x00}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &RenegotiationInfoExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestUnknownExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "unknown", &unknownExtension{
		typ: 0xBEEF,
		raw: []byte{0xde, 0xad, 0xbe, 0xef},
	})
}

func TestNewExtensionKnownTypes(t *testing.T) {
	tests := []struct {
		t    uint16
		want string
	}{
		{ExtServerName, "*dissector.ServerNameExtension"},
		{ExtSupportedGroups, "*dissector.SupportedGroupsExtension"},
		{ExtECPointFormats, "*dissector.ECPointFormatsExtension"},
		{ExtSignatureAlgorithms, "*dissector.SignatureAlgorithmsExtension"},
		{ExtALPN, "*dissector.ALPNExtension"},
		{ExtEncryptThenMac, "*dissector.EncryptThenMacExtension"},
		{ExtExtendedMasterSecret, "*dissector.ExtendedMasterSecretExtension"},
		{ExtSessionTicket, "*dissector.SessionTicketExtension"},
		{ExtSupportedVersions, "*dissector.SupportedVersionsExtension"},
		{ExtKeyShare, "*dissector.KeyShareExtension"},
		{ExtPreSharedKey, "*dissector.PreSharedKeyExtension"},
		{ExtPskKeyExchangeModes, "*dissector.PskKeyExchangeModesExtension"},
		{ExtSignatureAlgorithmsCert, "*dissector.SignatureAlgorithmsCertExtension"},
		{ExtCookie, "*dissector.CookieExtension"},
		{ExtEarlyData, "*dissector.EarlyDataExtension"},
		{ExtRenegotiationInfo, "*dissector.RenegotiationInfoExtension"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			ext, err := NewExtension(tt.t, nil)
			if err != nil {
				t.Fatalf("NewExtension error: %v", err)
			}
			typeName := reflect.TypeOf(ext).String()
			if typeName != tt.want {
				t.Errorf("type = %s, want %s", typeName, tt.want)
			}
			if ext.Type() != tt.t {
				t.Errorf("Type() = %#x, want %#x", ext.Type(), tt.t)
			}
		})
	}
}

func TestNewExtensionUnknown(t *testing.T) {
	ext, err := NewExtension(0xBEEF, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("NewExtension error: %v", err)
	}
	if ext.Type() != 0xBEEF {
		t.Errorf("Type() = %#x, want %#x", ext.Type(), 0xBEEF)
	}

	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if !bytes.Equal(encoded, []byte{0x01, 0x02}) {
		t.Errorf("encoded = %v, want [1 2]", encoded)
	}
}

func TestReadExtension(t *testing.T) {
	data := []byte{
		0x00, 0x00, // type: SNI
		0x00, 0x0c, // length: 12
		// SNI data:
		0x00, 0x0a, // list length: 10
		0x00,       // name type: host_name
		0x00, 0x07, // name length: 7
		'e', 'x', 'a', 'm', 'p', 'l', 'e',
	}
	ext, err := ReadExtension(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadExtension error: %v", err)
	}
	if ext.Type() != ExtServerName {
		t.Errorf("type = %#x, want %#x", ext.Type(), ExtServerName)
	}
	sni, ok := ext.(*ServerNameExtension)
	if !ok {
		t.Fatalf("wrong type: %T", ext)
	}
	if sni.Name != "example" {
		t.Errorf("Name = %q, want %q", sni.Name, "example")
	}
}

func TestReadExtensions(t *testing.T) {
	ext1 := &ServerNameExtension{NameType: 0, Name: "example.com"}
	ext2 := &ALPNExtension{Protos: []string{"h2"}}

	ed1, _ := ext1.Encode()
	ed2, _ := ext2.Encode()

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(ExtServerName >> 8))
	buf.WriteByte(byte(ExtServerName & 0xFF))
	buf.WriteByte(byte(len(ed1) >> 8))
	buf.WriteByte(byte(len(ed1) & 0xFF))
	buf.Write(ed1)
	buf.WriteByte(byte(ExtALPN >> 8))
	buf.WriteByte(byte(ExtALPN & 0xFF))
	buf.WriteByte(byte(len(ed2) >> 8))
	buf.WriteByte(byte(len(ed2) & 0xFF))
	buf.Write(ed2)

	exts, err := readExtensions(buf.Bytes())
	if err != nil {
		t.Fatalf("readExtensions error: %v", err)
	}
	if len(exts) != 2 {
		t.Fatalf("got %d extensions, want 2", len(exts))
	}
	if exts[0].Type() != ExtServerName {
		t.Errorf("ext[0] type = %#x, want %#x", exts[0].Type(), ExtServerName)
	}
	if exts[1].Type() != ExtALPN {
		t.Errorf("ext[1] type = %#x, want %#x", exts[1].Type(), ExtALPN)
	}
}

func TestReadExtensionsEmpty(t *testing.T) {
	exts, err := readExtensions([]byte{})
	if err != nil {
		t.Fatalf("readExtensions error: %v", err)
	}
	if len(exts) != 0 {
		t.Errorf("got %d extensions, want 0", len(exts))
	}
}

func TestReadExtension_TruncatedBody(t *testing.T) {
	// Header says body is 100 bytes, but only 3 follow
	data := []byte{0x00, 0x00, 0x00, 100, 0x01, 0x02}
	_, err := ReadExtension(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for truncated extension body")
	}
}

func TestReadExtensions_MidStreamError(t *testing.T) {
	// First extension is complete and valid, second is truncated
	ext1 := &ServerNameExtension{NameType: 0, Name: "example.com"}
	ed1, _ := ext1.Encode()

	buf := new(bytes.Buffer)
	// Valid first extension
	buf.WriteByte(byte(ExtServerName >> 8))
	buf.WriteByte(byte(ExtServerName & 0xFF))
	buf.WriteByte(byte(len(ed1) >> 8))
	buf.WriteByte(byte(len(ed1) & 0xFF))
	buf.Write(ed1)
	// Corrupt second extension: header says body is 200 bytes, but none follow
	buf.WriteByte(byte(ExtALPN >> 8))
	buf.WriteByte(byte(ExtALPN & 0xFF))
	buf.WriteByte(0x00)
	buf.WriteByte(200)

	_, err := readExtensions(buf.Bytes())
	if err == nil {
		t.Fatal("expected error from mid-stream extension read")
	}
}

func TestALPNExtensionDecode_MissingProtoLen(t *testing.T) {
	// ALPN list length says 2 bytes but there's only 1 (no room for proto length byte)
	ext := &ALPNExtension{}
	err := ext.Decode([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "short buffer") {
		t.Errorf("error = %q, want containing 'short buffer'", err.Error())
	}
}

func TestALPNExtensionDecode_TruncatedProto(t *testing.T) {
	// First proto reads fine (len=2, 'h2'), second proto claims 10 bytes but only 0 remain
	ext := &ALPNExtension{}
	err := ext.Decode([]byte{0x00, 0x04, 0x02, 0x68, 0x32, 0x0A})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "short buffer") {
		t.Errorf("error = %q, want containing 'short buffer'", err.Error())
	}
}

func TestSupportedVersionsExtensionEncode_Empty(t *testing.T) {
	ext := &SupportedVersionsExtension{Versions: nil}
	data, err := ext.Encode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data for empty versions, got %v", data)
	}
}

func TestSupportedVersionsExtensionDecode_ShortVersionList(t *testing.T) {
	// verLen says 4 bytes but only 2 follow after removing length byte
	ext := &SupportedVersionsExtension{}
	err := ext.Decode([]byte{0x04, 0x03, 0x04})
	if err == nil {
		t.Fatal("expected error for truncated version list")
	}
	if !strings.Contains(err.Error(), "short buffer") {
		t.Errorf("error = %q, want containing 'short buffer'", err.Error())
	}
}

func TestReadExtension_TruncatedHeader(t *testing.T) {
	// 3 bytes of a 4-byte extension header — io.ReadFull should fail
	_, err := ReadExtension(bytes.NewReader([]byte{0x00, 0x00, 0x00}))
	if err == nil {
		t.Fatal("expected error for truncated extension header")
	}
}

// Regression: BUG 2 — odd algorithm list length must return error, not panic
func TestSignatureAlgorithmsDecode_OddLength(t *testing.T) {
	data := []byte{0x00, 0x03, 0x04, 0x03, 0x05}
	ext := &SignatureAlgorithmsExtension{}
	err := ext.Decode(data)
	if err == nil {
		t.Fatal("expected error for odd algorithm list length")
	}
	if !strings.Contains(err.Error(), "odd") {
		t.Errorf("error = %q, want containing 'odd'", err.Error())
	}
}

// Regression: BUG 3 — versions with zeros must encode consistent length
func TestSupportedVersionsEncode_WithZeroVersions(t *testing.T) {
	ext := &SupportedVersionsExtension{
		Versions: []uint16{0x0304, 0x0000, 0x0303},
	}
	data, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if len(data) > 0 {
		claimedLen := int(data[0])
		actualLen := len(data) - 1
		if claimedLen != actualLen {
			t.Errorf("length mismatch: byte claims %d, but %d bytes follow", claimedLen, actualLen)
		}
		// Round-trip decode to verify
		decoded := &SupportedVersionsExtension{}
		if err := decoded.Decode(data); err != nil {
			t.Fatalf("Decode error: %v", err)
		}
		if len(decoded.Versions) != 2 {
			t.Errorf("decoded Versions count = %d, want 2 (zeros excluded)", len(decoded.Versions))
		}
	}
}

// Regression: BUG 4 — proto name >255 bytes must return error, not truncate
func TestALPNEncode_LongProtoName(t *testing.T) {
	longName := make([]byte, 300)
	for i := range longName {
		longName[i] = 'x'
	}
	ext := &ALPNExtension{
		Protos: []string{string(longName)},
	}
	_, err := ext.Encode()
	if err == nil {
		t.Fatal("expected error for proto name exceeding 255 bytes")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("error = %q, want containing 'too long'", err.Error())
	}
}

func TestSupportedVersionsExtensionServerZeroVersion(t *testing.T) {
	ext := &SupportedVersionsExtension{
		Versions: []uint16{0x0000},
		Server:   true,
	}
	data, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if len(data) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(data))
	}
	// Round-trip: Decode should produce Server=true with Version=[0]
	decoded := &SupportedVersionsExtension{}
	if err := decoded.Decode(data); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if len(decoded.Versions) != 1 || decoded.Versions[0] != 0 {
		t.Errorf("Versions = %v, want [0]", decoded.Versions)
	}
	if !decoded.Server {
		t.Error("Server should be true")
	}
}

func TestSignatureAlgorithmsDecode_ValidTwoByteList(t *testing.T) {
	ext := &SignatureAlgorithmsExtension{}
	err := ext.Decode([]byte{0x00, 0x02, 0x04, 0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ext.Algorithms) != 1 || ext.Algorithms[0] != 0x0403 {
		t.Errorf("Algorithms = %v, want [0403]", ext.Algorithms)
	}
}

func TestKeyShareExtensionClientHello(t *testing.T) {
	extRoundTrip(t, "key_share_ch", &KeyShareExtension{
		Entries: []KeyShareEntry{
			{Group: 0x001D, KeyExchange: make([]byte, 32)},
			{Group: 0x0017, KeyExchange: make([]byte, 65)},
		},
	})
}

func TestKeyShareExtensionServerHello(t *testing.T) {
	ks := make([]byte, 32)
	extRoundTrip(t, "key_share_sh", &KeyShareExtension{
		Entries: []KeyShareEntry{{Group: 0x001D, KeyExchange: ks}},
		Server:  true,
	})
}

func TestKeyShareExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"truncated body", []byte{0x00, 0x0a, 0x00}, "short buffer"},
		{"truncated entry", []byte{0x00, 0x06, 0x00, 0x1D, 0x00, 0x20}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &KeyShareExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestPskKeyExchangeModesExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "psk_kex_modes", &PskKeyExchangeModesExtension{
		Modes: []uint8{0, 1},
	})
}

func TestPskKeyExchangeModesExtensionEmpty(t *testing.T) {
	extRoundTrip(t, "psk_kex_modes_empty", &PskKeyExchangeModesExtension{})
}

func TestPskKeyExchangeModesExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{}, "short buffer"},
		{"truncated list", []byte{0x03, 0x00}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &PskKeyExchangeModesExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestPreSharedKeyExtensionClientHello(t *testing.T) {
	extRoundTrip(t, "psk_ch", &PreSharedKeyExtension{
		Identities: []PskIdentity{
			{Identity: []byte("ticket-1"), ObfuscatedTicketAge: 3600},
			{Identity: []byte("ticket-2"), ObfuscatedTicketAge: 7200},
		},
		Binders: [][]byte{
			make([]byte, 32),
			make([]byte, 32),
		},
	})
}

func TestPreSharedKeyExtensionServerHello(t *testing.T) {
	extRoundTrip(t, "psk_sh", &PreSharedKeyExtension{
		SelectedIdentity: 1,
		Server:           true,
	})
}

func TestPreSharedKeyExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"truncated identities", []byte{0x00, 0x0a, 0x00, 0x08}, "short buffer"},
		{"truncated identity entry", []byte{0x00, 0x0a, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &PreSharedKeyExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSignatureAlgorithmsCertExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "sig_algs_cert", &SignatureAlgorithmsCertExtension{
		Algorithms: []uint16{0x0403, 0x0503, 0x0603},
	})
}

func TestSignatureAlgorithmsCertExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"odd length", []byte{0x00, 0x03, 0x04, 0x03}, "odd algorithm list length"},
		{"truncated data", []byte{0x00, 0x06, 0x04, 0x03}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &SignatureAlgorithmsCertExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCookieExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "cookie", &CookieExtension{
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	})
}

func TestCookieExtensionEmpty(t *testing.T) {
	extRoundTrip(t, "cookie_empty", &CookieExtension{})
}

func TestCookieExtensionDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"too short", []byte{0x00}, "short buffer"},
		{"truncated data", []byte{0x00, 0x0a, 0x01, 0x02}, "short buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &CookieExtension{}
			err := ext.Decode(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEarlyDataExtensionRoundTrip(t *testing.T) {
	extRoundTrip(t, "early_data", &EarlyDataExtension{})
}

func TestEarlyDataExtensionDecodeArbitrary(t *testing.T) {
	ext := &EarlyDataExtension{}
	// early_data is a signal-only extension — any data is silently accepted
	if err := ext.Decode([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	data, err := ext.Encode()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty output, got %v", data)
	}
}
