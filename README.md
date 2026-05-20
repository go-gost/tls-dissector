# tls-dissector

Zero-dependency Go library for dissecting TLS ClientHello and ServerHello handshake messages at the record layer. Used in proxy/gateway scenarios to extract routing-relevant fields (SNI, ALPN, cipher suites, supported versions) without fully terminating TLS.

## Installation

```sh
go get github.com/go-gost/tls-dissector
```

Requires Go 1.17+. No external dependencies.

## Usage

```go
import dissector "github.com/go-gost/tls-dissector"

// Parse a ClientHello from any io.Reader (e.g., a buffered TLS connection)
info, err := dissector.ParseClientHello(reader)
// info.ServerName        → "example.com"   (SNI)
// info.SupportedVersions → []uint16{0x0304} (TLS 1.3)
// info.SupportedProtos   → []string{"h2", "http/1.1"}  (ALPN)
// info.CipherSuites      → []uint16{0xC02B, 0xC02F}

// Parse a ServerHello
resp, err := dissector.ParseServerHello(reader)
// resp.Proto   → "h2"          (negotiated ALPN)
// resp.Version → 0x0304        (negotiated version)
```

## How it works

Data flows through four layers:

1. **TLS Record** — `ReadRecord` consumes a 5-byte header + payload, checking the content type (Handshake, Alert, etc.)
2. **Handshake** — the record payload is decoded as a `ClientHelloMsg` or `ServerHelloMsg`, with length-prefixed fields parsed sequentially
3. **Extensions** — the trailing extension block is parsed into typed extension structs via the `Extension` interface
4. **Info extraction** — relevant fields are pulled from the messages and extensions into flat `ClientHelloInfo` / `ServerHelloInfo` structs

The library is a **passthrough parser**: only ClientHello and ServerHello are understood. Other handshake messages are not parsed. Each handshake message is assumed to fit in a single TLS record (no fragmentation support).

## API

```go
// Top-level parse functions
func ParseClientHello(r io.Reader) (*ClientHelloInfo, error)
func ParseServerHello(r io.Reader) (*ServerHelloInfo, error)

// Record layer
func ReadRecord(r io.Reader) (*Record, error)

// Extension system
type Extension interface {
    Type() uint16
    Encode() ([]byte, error)
    Decode([]byte) error
}
func NewExtension(t uint16, data []byte) (Extension, error)
func ReadExtension(r io.Reader) (Extension, error)

// Sentinel errors
var ErrBadType = errors.New("bad type")
var ErrAlert   = errors.New("alert")
```

`ParseServerHello` handles both Handshake (0x16) and EncryptedAlert (0x15) record types. When the server responds with an alert, it returns `ErrAlert` wrapping the alert level and description.

## Supported TLS extensions

| Name | Value | RFC |
|------|-------|-----|
| Server Name (SNI) | 0x0000 | RFC 6066 |
| Supported Groups | 0x000a | RFC 7919 |
| EC Point Formats | 0x000b | RFC 4492 |
| Signature Algorithms | 0x000d | RFC 5246 |
| ALPN | 0x0010 | RFC 7301 |
| Encrypt-then-MAC | 0x0016 | RFC 7366 |
| Extended Master Secret | 0x0017 | RFC 7627 |
| Session Ticket | 0x0023 | RFC 5077 |
| Supported Versions | 0x002b | RFC 8446 |
| Renegotiation Info | 0xff01 | RFC 5746 |

Unknown extensions are preserved as opaque bytes. New extensions can be added by implementing the `Extension` interface and registering in `NewExtension`.

## Tests

```sh
go test -v -cover ./...
```

Coverage: 99.8% across 4 test files covering record parsing, handshake messages, all 11 extensions, and end-to-end parse functions.

## License

MIT — see [LICENSE](LICENSE).
