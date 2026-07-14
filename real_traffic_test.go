package dissector

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParseClientHello_RealTraffic(t *testing.T) {
	tests := []struct {
		name     string
		hexData  string // full TLS record including 5-byte header
		wantSNI  string
		wantALPN []string
		wantVer  uint16 // expected handshake version (0x0303=TLS 1.2, 0x0304=TLS 1.3 via supported_versions)
	}{
		{
			name: "cloudflare-quic.com",
			hexData: "160301013a010001360303d0c13e538a2bf6f73d50b151cf02629d15d9b49fbd589ef4472f71c16d5203e520aa7775f73feb9cee597c57aeaeae30b2bb9cfd6622815072ba2cea00c17aba530026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c7000000180016000013636c6f7564666c6172652d717569632e636f6d000b00020100ff010001000017000000120000000500050100000000000a000a0008001d001700180019000d001a00180804040308070805080604010501060105030603020102030032001a00180804040308070805080604010501060105030603020102030010000e000c02683208687474702f312e31002b00050403040303003300260024001d0020eefe8c9fab6c9c521ce4e09a3f4b34065ef7374da0a542503378b8e0cabc9f4b",
			wantSNI: "cloudflare-quic.com",
			wantALPN: []string{"h2", "http/1.1"},
			wantVer: 0x0304,
		},
		{
			name: "cloudflare-quic.com-tls12",
			hexData: "1603010108010001040303b07c08a02763b05d208cc396e41b4aaba19e76a31360b26660a6ae0ede5d9a4e20832c330fc1dc340691502a3e00dca39e846cfdb4e38327b37e087b6bf91725820020c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a0100009b000000180016000013636c6f7564666c6172652d717569632e636f6d000b00020100ff010001000017000000120000000500050100000000000a000a0008001d001700180019000d001a00180804040308070805080604010501060105030603020102030032001a00180804040308070805080604010501060105030603020102030010000e000c02683208687474702f312e31002b0003020303",
			wantSNI: "cloudflare-quic.com",
			wantALPN: []string{"h2", "http/1.1"},
			wantVer: 0x0303,
		},
		{
			name: "cloudflare-quic.com-tls10",
			hexData: "16030100aa010000a603018ec651a2510aac1c8067d2147a6d0bf4e6b5e57b92fe8bee8ceaf37eae974bdb20e3196b781bd3a3e60f499954f939cd702b127c0c0597e4cad294c6aded3c877e0010c009c013c00ac014002f0035c012000a0100004d000000180016000013636c6f7564666c6172652d717569632e636f6d000b00020100ff010001000017000000120000000500050100000000000a000a0008001d001700180019002b0003020301",
			wantSNI: "cloudflare-quic.com",
			wantALPN: nil,
			wantVer: 0x0301,
		},
		{
			name: "www.google.com",
			hexData: "1603010135010001310303423d22f97d9fc74550ed6136e035779b5eaabcefa4e79b148ac05e06abe14fa52094e8691210d8100f7ebd19494e3c97455978252eb7d443a11a3c50ed7c29ffcf0026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000c200000013001100000e7777772e676f6f676c652e636f6d000b00020100ff010001000017000000120000000500050100000000000a000a0008001d001700180019000d001a00180804040308070805080604010501060105030603020102030032001a00180804040308070805080604010501060105030603020102030010000e000c02683208687474702f312e31002b00050403040303003300260024001d0020d274ee0871450294ee933acf39cde7bb7ad08c8539693a689c45146fe49db400",
			wantSNI: "www.google.com",
			wantALPN: []string{"h2", "http/1.1"},
			wantVer: 0x0304,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.hexData)
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			t.Logf("record: %d bytes, type=0x%02x", len(data), data[0])

			info, err := ParseClientHello(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}

			t.Logf("SNI=%q  ALPN=%v  Ciphers=%d", info.ServerName, info.SupportedProtos, len(info.CipherSuites))
			if info.ServerName != tc.wantSNI {
				t.Errorf("ServerName = %q, want %q", info.ServerName, tc.wantSNI)
			}
			if len(info.SupportedVersions) > 0 && info.SupportedVersions[0] != tc.wantVer {
				t.Errorf("Version = 0x%04x, want 0x%04x", info.SupportedVersions[0], tc.wantVer)
			}
			if len(info.SupportedProtos) > 0 {
				for i, p := range tc.wantALPN {
					if i >= len(info.SupportedProtos) || info.SupportedProtos[i] != p {
						t.Errorf("ALPN[%d] = %q, want %q", i, info.SupportedProtos[i], p)
					}
				}
			}
		})
	}
}

func TestParseServerHello_RealTraffic(t *testing.T) {
	tests := []struct {
		name       string
		hexData    string
		wantCipher uint16
		wantVer    uint16
	}{
		{
			name:       "cloudflare-quic.com-tls13",
			hexData:    "160303007a020000760303c0f055977763a16aaa37d9515c3b6d78475caa7afe8da5e9eb8f5af08e4eaafd20ebe8ac99a0ad5f34ecff32cd9a081a65751a4a04ec9f88c45b8f9befd09b7221130100002e00330024001d00202df74949f31f61eab7834a62a314b0926b356717849e99d79ce328ec74858e33002b00020304",
			wantCipher: 0x1301,
			wantVer:    0x0304,
		},
		{
			name:       "cloudflare-quic.com-tls12",
			hexData:    "16030300630200005f03036a563e82e6a4f553e63a0c87608b509d6a6153e3f4c4b34f444f574e4752440120caed36287a84815f8abcb014df2528f46b6edfac972389c5efc53e8fd8e27c1fc02b0000170000000000170000ff01000100000b0002010000050000",
			wantCipher: 0xc02b,
			wantVer:    0x0303,
		},
		{
			name:       "www.google.com-tls10",
			hexData:    "160301003b0200003703016a563e86ef33029904b42aebadbd105be49775733327528e444f574e4752440000c00900000f00170000ff01000100000b00020100",
			wantCipher: 0xc009,
			wantVer:    0x0301,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.hexData)
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			info, err := ParseServerHello(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseServerHello: %v", err)
			}
			if info.CipherSuite != tc.wantCipher {
				t.Errorf("CipherSuite = 0x%04x, want 0x%04x", info.CipherSuite, tc.wantCipher)
			}
			if info.Version != tc.wantVer {
				t.Errorf("Version = 0x%04x, want 0x%04x", info.Version, tc.wantVer)
			}
			if info.CompressionMethod != 0 {
				t.Errorf("CompressionMethod = 0x%02x, want 0x00", info.CompressionMethod)
			}
			t.Logf("Version=0x%04x CipherSuite=0x%04x Compression=0x%02x Proto=%q",
				info.Version, info.CipherSuite, info.CompressionMethod, info.Proto)
		})
	}
}
