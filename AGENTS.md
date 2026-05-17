# tls-dissector (TLS Handshake Dissector)

Zero-dependency Go library for parsing TLS ClientHello and ServerHello handshake messages at the record layer. Used for extracting routing-relevant fields (SNI, ALPN, cipher suites, supported versions) in proxy/gateway scenarios.

## Module

```
github.com/go-gost/tls-dissector
```

Go 1.17+. No external dependencies (only Go standard library).

## Package layout

| File | Lines | Layer |
|------|-------|-------|
| `dissector.go` | 109 | Public API: `ParseClientHello`, `ParseServerHello`, `ClientHelloInfo`, `ServerHelloInfo` |
| `record.go` | 67 | TLS Record layer: `ReadRecord`, `Record`, content type constants |
| `msg.go` | 522 | Handshake message types: `ClientHelloMsg`, `ServerHelloMsg`, `AlertMsg`, `Random` |
| `extension.go` | 457 | Extension system: `Extension` interface, 11 concrete types, `NewExtension` factory |

## Public API

### Parsing functions

```go
func ParseClientHello(r io.Reader) (*ClientHelloInfo, error)
func ParseServerHello(r io.Reader) (*ServerHelloInfo, error)
```

`ParseServerHello` handles both `Handshake` (0x16) and `EncryptedAlert` (0x15) record types. On alert, it returns `ErrAlert` with the alert level and description string.

### Output types

```go
type ClientHelloInfo struct {
    SessionID          []byte
    CipherSuites       []uint16
    CompressionMethods []uint8
    SupportedProtos    []string   // from ALPN extension
    SupportedVersions  []uint16   // from supported_versions extension
    ServerName         string     // from SNI extension
}

type ServerHelloInfo struct {
    SessionID         []byte
    CipherSuite       uint16
    CompressionMethod uint8
    Proto             string   // from ALPN extension
    Version           uint16   // from supported_versions extension, or TLS 1.2 default
}
```

### Record layer

```go
func ReadRecord(r io.Reader) (*Record, error)

type Record struct {
    Type    uint8
    Version Version
    Opaque  []byte
}
```

### Extension system

```go
type Extension interface {
    Type() uint16
    Encode() ([]byte, error)
    Decode([]byte) error
}

func NewExtension(t uint16, data []byte) (Extension, error)  // factory
func ReadExtension(r io.Reader) (Extension, error)           // read from stream
```

### Message types

All message types implement `ReadFrom(io.Reader)`, `WriteTo(io.Writer)`, `Decode([]byte)`, `Encode() ([]byte, error)`:
- `ClientHelloMsg`, `ServerHelloMsg`, `AlertMsg`

### Sentinel errors

```go
ErrBadType  // wrong record or handshake message type
ErrAlert    // server responded with an alert (ParseServerHello only)
```

## Supported TLS extensions

| Constant | Value | RFC |
|----------|-------|-----|
| `ExtServerName` | 0x0000 | RFC 6066 (SNI) |
| `ExtSupportedGroups` | 0x000a | RFC 7919/8446 |
| `ExtECPointFormats` | 0x000b | RFC 4492 |
| `ExtSignatureAlgorithms` | 0x000d | RFC 5246 |
| `ExtALPN` | 0x0010 | RFC 7301 |
| `ExtEncryptThenMac` | 0x0016 | RFC 7366 |
| `ExtExtendedMasterSecret` | 0x0017 | RFC 7627 |
| `ExtSessionTicket` | 0x0023 | RFC 5077 |
| `ExtSupportedVersions` | 0x002b | RFC 8446 (TLS 1.3) |
| `ExtRenegotiationInfo` | 0xff01 | RFC 5746 |

Unknown extensions are preserved as `unknownExtension` (raw bytes passthrough).

## Design notes

- **Passthrough parser only**: only ClientHello and ServerHello are parsed. No Certificate, ServerKeyExchange, Finished, or other handshake messages.
- **No record fragmentation**: assumes each handshake message fits in a single TLS record.
- **Bidirectional**: all types support both encoding and decoding.
- **Extensible**: new extensions can be added by implementing the `Extension` interface and adding a case to `NewExtension`.

## Testing

```sh
cd tls-dissector && go test ./...
```

There are currently no tests.

## Related modules

- `core/` — defines `service.Service` interface (uses tls-dissector indirectly via `x/`)
- `x/` — all protocol implementations that depend on this module for TLS inspection
- `gost/` — main binary that integrates TLS dissection into proxy routing
