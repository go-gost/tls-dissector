# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
cd tls-dissector

# Build (single package, no external deps)
go build ./...

# Lint
go vet ./...

# Run all tests with coverage
go test -v -cover ./...

# Run a single test
go test -v -run TestParseClientHello ./...
```

Module: `github.com/go-gost/tls-dissector` — Go 1.17+, zero dependencies beyond stdlib.

## Architecture

Four layers, each in its own file, stacked bottom-up:

| Layer | File | Responsibility |
|-------|------|----------------|
| Record | `record.go` | TLS record framing: `ReadRecord`, `Record` struct, content type constants |
| Handshake | `msg.go` | `ClientHelloMsg`, `ServerHelloMsg`, `AlertMsg` — each with `ReadFrom`/`WriteTo`/`Decode`/`Encode` |
| Extensions | `extension.go` | `Extension` interface + 11 concrete types + `NewExtension` factory |
| Public API | `dissector.go` | `ParseClientHello`, `ParseServerHello`, `ClientHelloInfo`, `ServerHelloInfo` |

**Data flow**: raw bytes → `ReadRecord` (TLS record) → handshake message `Decode` → extension extraction → info structs.

**Only ClientHello and ServerHello are parsed.** No Certificate, ServerKeyExchange, Finished, or other handshake messages. Assumes each handshake message fits in a single TLS record (no fragmentation).

## Key patterns

- **Bidirectional**: every type supports both encode and decode (used in tests for round-trip assertions).
- **Extension system**: new extensions implement the `Extension` interface and add a case to `NewExtension`. Unknown types are preserved as `unknownExtension` (raw bytes passthrough).
- **Sentinel errors**: `ErrBadType` (wrong record/message type), `ErrAlert` (server alert response), `ErrShortBuffer`, `ErrTypeMismatch`.
- **`Version`** is a `uint16` type alias defined in `record.go`, validated against `crypto/tls` range (TLS 1.0–1.3).
- **`Random`** is a struct with `Time uint32` + `Opaque [28]byte` defined in `msg.go`.

## Testing

Tests use captured TLS handshake bytes from real connections (stored as inline hex dumps). Test strategy: encode a known-good message, then round-trip through decode/encode and compare. Coverage: 99.8% across 4 test files.
