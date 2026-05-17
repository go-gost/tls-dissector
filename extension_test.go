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
		0x00,                   // name type: host_name
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

func TestReadExtensionTruncated(t *testing.T) {
	_, err := ReadExtension(bytes.NewReader([]byte{0x00, 0x00, 0x00}))
	if err == nil {
		t.Fatal("expected error for truncated extension header")
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
