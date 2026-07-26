package dissector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	extensionHeaderLen = 4
)

const (
	ExtServerName              uint16 = 0x00
	ExtSupportedGroups         uint16 = 0x0a
	ExtECPointFormats          uint16 = 0x0b
	ExtSignatureAlgorithms     uint16 = 0x0d
	ExtALPN                    uint16 = 0x10
	ExtEncryptThenMac          uint16 = 0x16
	ExtExtendedMasterSecret    uint16 = 0x17
	ExtSessionTicket           uint16 = 0x23
	ExtPreSharedKey            uint16 = 0x29
	ExtEarlyData               uint16 = 0x2a
	ExtSupportedVersions       uint16 = 0x2b
	ExtCookie                  uint16 = 0x2c
	ExtPskKeyExchangeModes     uint16 = 0x2d
	ExtSignatureAlgorithmsCert uint16 = 0x32
	ExtKeyShare                uint16 = 0x33
	ExtRenegotiationInfo       uint16 = 0xff01
)

var (
	ErrShortBuffer  = errors.New("short buffer")
	ErrTypeMismatch = errors.New("type mismatch")
)

type Extension interface {
	Type() uint16
	Encode() ([]byte, error)
	Decode([]byte) error
}

func NewExtension(t uint16, data []byte) (ext Extension, err error) {
	switch t {
	case ExtServerName:
		ext = new(ServerNameExtension)
	case ExtSupportedGroups:
		ext = new(SupportedGroupsExtension)
	case ExtECPointFormats:
		ext = new(ECPointFormatsExtension)
	case ExtSignatureAlgorithms:
		ext = new(SignatureAlgorithmsExtension)
	case ExtALPN:
		ext = new(ALPNExtension)
	case ExtEncryptThenMac:
		ext = new(EncryptThenMacExtension)
	case ExtExtendedMasterSecret:
		ext = new(ExtendedMasterSecretExtension)
	case ExtSessionTicket:
		ext = new(SessionTicketExtension)
	case ExtSupportedVersions:
		ext = new(SupportedVersionsExtension)
	case ExtKeyShare:
		ext = new(KeyShareExtension)
	case ExtPreSharedKey:
		ext = new(PreSharedKeyExtension)
	case ExtPskKeyExchangeModes:
		ext = new(PskKeyExchangeModesExtension)
	case ExtSignatureAlgorithmsCert:
		ext = new(SignatureAlgorithmsCertExtension)
	case ExtCookie:
		ext = new(CookieExtension)
	case ExtEarlyData:
		ext = new(EarlyDataExtension)
	case ExtRenegotiationInfo:
		ext = new(RenegotiationInfoExtension)
	default:
		ext = &unknownExtension{
			typ: t,
		}
	}
	if len(data) > 0 {
		err = ext.Decode(data)
	}
	return
}

func ReadExtension(r io.Reader) (Extension, error) {
	var b [extensionHeaderLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	t := binary.BigEndian.Uint16(b[:2])
	bb := make([]byte, int(binary.BigEndian.Uint16(b[2:4])))
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}

	return NewExtension(t, bb)
}

func readExtensions(b []byte) (exts []Extension, err error) {
	if len(b) == 0 {
		return
	}

	br := bytes.NewReader(b)
	for br.Len() > 0 {
		var ext Extension
		ext, err = ReadExtension(br)
		if err != nil {
			return
		}
		exts = append(exts, ext)
	}
	return
}

type unknownExtension struct {
	typ uint16
	raw []byte
}

func (ext *unknownExtension) Type() uint16 {
	return ext.typ
}

func (ext *unknownExtension) Encode() ([]byte, error) {
	return ext.raw, nil
}

func (ext *unknownExtension) Decode(b []byte) error {
	ext.raw = make([]byte, len(b))
	copy(ext.raw, b)
	return nil
}

type ServerNameExtension struct {
	NameType uint8
	Name     string
}

func (ext *ServerNameExtension) Type() uint16 {
	return ExtServerName
}

func (ext *ServerNameExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(1+2+len(ext.Name)))
	buf.WriteByte(ext.NameType)
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Name)))
	buf.WriteString(ext.Name)
	return buf.Bytes(), nil
}

func (ext *ServerNameExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("server_name: %w", ErrShortBuffer)
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	if len(b[2:]) < listLen {
		return fmt.Errorf("server_name: %w", ErrShortBuffer)
	}
	b = b[2 : 2+listLen]

	if len(b) < 3 {
		return fmt.Errorf("server_name: %w", ErrShortBuffer)
	}

	ext.NameType = b[0]
	n := int(binary.BigEndian.Uint16(b[1:]))
	if len(b[3:]) < n {
		return fmt.Errorf("server_name: %w", ErrShortBuffer)
	}
	ext.Name = string(b[3 : 3+n])
	return nil
}

type SessionTicketExtension struct {
	Data []byte
}

func (ext *SessionTicketExtension) Type() uint16 {
	return ExtSessionTicket
}

func (ext *SessionTicketExtension) Encode() ([]byte, error) {
	return ext.Data, nil
}

func (ext *SessionTicketExtension) Decode(b []byte) error {
	ext.Data = make([]byte, len(b))
	copy(ext.Data, b)
	return nil
}

type ECPointFormatsExtension struct {
	Formats []uint8
}

func (ext *ECPointFormatsExtension) Type() uint16 {
	return ExtECPointFormats
}

func (ext *ECPointFormatsExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(uint8(len(ext.Formats)))
	buf.Write(ext.Formats)
	return buf.Bytes(), nil
}

func (ext *ECPointFormatsExtension) Decode(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("ec_point_formats: %w", ErrShortBuffer)
	}

	n := int(b[0])
	if len(b[1:]) < n {
		return fmt.Errorf("ec_point_formats: %w", ErrShortBuffer)
	}

	ext.Formats = make([]byte, n)
	copy(ext.Formats, b[1:])
	return nil
}

type SupportedGroupsExtension struct {
	Groups []uint16
}

func (ext *SupportedGroupsExtension) Type() uint16 {
	return ExtSupportedGroups
}

func (ext *SupportedGroupsExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Groups)*2))
	for _, group := range ext.Groups {
		binary.Write(buf, binary.BigEndian, group)
	}
	return buf.Bytes(), nil
}

func (ext *SupportedGroupsExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("supported_groups: %w", ErrShortBuffer)
	}

	n := int(binary.BigEndian.Uint16(b))
	if n%2 != 0 {
		return fmt.Errorf("supported_groups: odd group list length %d", n)
	}
	if len(b[2:]) < n {
		return fmt.Errorf("supported_groups: %w", ErrShortBuffer)
	}

	ext.Groups = make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		ext.Groups = append(ext.Groups, binary.BigEndian.Uint16(b[2+i:]))
	}
	return nil
}

type SignatureAlgorithmsExtension struct {
	Algorithms []uint16
}

func (ext *SignatureAlgorithmsExtension) Type() uint16 {
	return ExtSignatureAlgorithms
}

func (ext *SignatureAlgorithmsExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Algorithms)*2))
	for _, alg := range ext.Algorithms {
		binary.Write(buf, binary.BigEndian, alg)
	}
	return buf.Bytes(), nil
}

func (ext *SignatureAlgorithmsExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("signature_algorithms: %w", ErrShortBuffer)
	}

	n := int(binary.BigEndian.Uint16(b))
	if n%2 != 0 {
		return fmt.Errorf("signature_algorithms: odd algorithm list length %d", n)
	}
	if len(b[2:]) < n {
		return fmt.Errorf("signature_algorithms: %w", ErrShortBuffer)
	}

	ext.Algorithms = make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		ext.Algorithms = append(ext.Algorithms, binary.BigEndian.Uint16(b[2+i:]))
	}
	return nil
}

type EncryptThenMacExtension struct {
	Data []byte
}

func (ext *EncryptThenMacExtension) Type() uint16 {
	return ExtEncryptThenMac
}

func (ext *EncryptThenMacExtension) Encode() ([]byte, error) {
	return ext.Data, nil
}

func (ext *EncryptThenMacExtension) Decode(b []byte) error {
	ext.Data = make([]byte, len(b))
	copy(ext.Data, b)
	return nil
}

type ExtendedMasterSecretExtension struct {
	Data []byte
}

func (ext *ExtendedMasterSecretExtension) Type() uint16 {
	return ExtExtendedMasterSecret
}

func (ext *ExtendedMasterSecretExtension) Encode() ([]byte, error) {
	return ext.Data, nil
}

func (ext *ExtendedMasterSecretExtension) Decode(b []byte) error {
	ext.Data = make([]byte, len(b))
	copy(ext.Data, b)
	return nil
}

type RenegotiationInfoExtension struct {
	Data []byte
}

func (ext *RenegotiationInfoExtension) Type() uint16 {
	return ExtRenegotiationInfo
}

func (ext *RenegotiationInfoExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(uint8(len(ext.Data)))
	buf.Write(ext.Data)
	return buf.Bytes(), nil
}

func (ext *RenegotiationInfoExtension) Decode(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("renegotiation_info: %w", ErrShortBuffer)
	}

	n := int(b[0])
	if len(b[1:]) < n {
		return fmt.Errorf("renegotiation_info: %w", ErrShortBuffer)
	}
	ext.Data = make([]byte, n)
	copy(ext.Data, b[1:])

	return nil
}

type ALPNExtension struct {
	Protos []string
}

func (ext *ALPNExtension) Type() uint16 {
	return ExtALPN
}

func (ext *ALPNExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0, 0}) // reserved 2-byte length

	for _, proto := range ext.Protos {
		if proto == "" {
			continue
		}
		if len(proto) > 255 {
			return nil, fmt.Errorf("application_layer_protocol_negotiation: proto name too long (%d bytes)", len(proto))
		}
		buf.WriteByte(uint8(len(proto))) // proto value length
		buf.WriteString(proto)
	}

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[:2], uint16(len(data)-2))
	return data, nil
}

func (ext *ALPNExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("application_layer_protocol_negotiation: %w", ErrShortBuffer)
	}

	alpnLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < alpnLen {
		return fmt.Errorf("application_layer_protocol_negotiation: %w", ErrShortBuffer)
	}
	b = b[:alpnLen]

	for len(b) > 0 {
		if len(b) < 1 {
			return fmt.Errorf("application_layer_protocol_negotiation: %w", ErrShortBuffer)
		}
		n := int(b[0])
		if len(b[1:]) < n {
			return fmt.Errorf("application_layer_protocol_negotiation: %w", ErrShortBuffer)
		}

		if proto := string(b[1 : 1+n]); proto != "" {
			ext.Protos = append(ext.Protos, proto)
		}

		b = b[1+n:]
	}

	return nil
}

type SupportedVersionsExtension struct {
	Versions []uint16
	Server   bool
}

func (ext *SupportedVersionsExtension) Type() uint16 {
	return ExtSupportedVersions
}

func (ext *SupportedVersionsExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	if len(ext.Versions) == 0 {
		return nil, nil
	}

	if ext.Server {
		var ver [2]byte
		binary.BigEndian.PutUint16(ver[:], ext.Versions[0])
		buf.Write(ver[:])
		return buf.Bytes(), nil
	}

	// Count non-zero versions to compute accurate length
	var count int
	for _, v := range ext.Versions {
		if v != 0 {
			count++
		}
	}
	buf.WriteByte(uint8(count * 2))

	for _, version := range ext.Versions {
		if version == 0 {
			continue
		}

		var ver [2]byte
		binary.BigEndian.PutUint16(ver[:], version)
		buf.Write(ver[:])
	}

	return buf.Bytes(), nil
}

func (ext *SupportedVersionsExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("supported_versions: %w", ErrShortBuffer)
	}

	if len(b) == 2 {
		ext.Versions = append(ext.Versions, binary.BigEndian.Uint16(b))
		ext.Server = true
		return nil
	}

	verLen := int(b[0])
	b = b[1:]
	if len(b) < verLen {
		return fmt.Errorf("supported_versions: %w", ErrShortBuffer)
	}
	if verLen%2 != 0 {
		return fmt.Errorf("supported_versions: odd version list length %d", verLen)
	}
	b = b[:verLen]

	for len(b) > 0 {
		ver := binary.BigEndian.Uint16(b[:2])
		ext.Versions = append(ext.Versions, ver)
		b = b[2:]
	}

	return nil
}

type KeyShareEntry struct {
	Group       uint16
	KeyExchange []byte
}

type KeyShareExtension struct {
	Entries []KeyShareEntry
	Server  bool
}

func (ext *KeyShareExtension) Type() uint16 {
	return ExtKeyShare
}

func (ext *KeyShareExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	if ext.Server {
		if len(ext.Entries) == 0 {
			return nil, nil
		}
		e := ext.Entries[0]
		binary.Write(buf, binary.BigEndian, e.Group)
		binary.Write(buf, binary.BigEndian, uint16(len(e.KeyExchange)))
		buf.Write(e.KeyExchange)
		return buf.Bytes(), nil
	}

	// ClientHello: 2-byte total length + entries
	body := &bytes.Buffer{}
	for _, e := range ext.Entries {
		binary.Write(body, binary.BigEndian, e.Group)
		binary.Write(body, binary.BigEndian, uint16(len(e.KeyExchange)))
		body.Write(e.KeyExchange)
	}
	binary.Write(buf, binary.BigEndian, uint16(body.Len()))
	buf.Write(body.Bytes())
	return buf.Bytes(), nil
}

func (ext *KeyShareExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("key_share: %w", ErrShortBuffer)
	}

	// HelloRetryRequest key_share (RFC 8446 §4.2.8): 2 bytes, just the
	// selected NamedGroup, no key_exchange field.  A ClientHello with
	// bodyLen=0 (0x0000) stays a no-op empty key_share as before.
	if len(b) == 2 {
		n := int(binary.BigEndian.Uint16(b[:2]))
		if n == 0 {
			return nil // ClientHello with empty client_shares
		}
		ext.Server = true
		ext.Entries = append(ext.Entries, KeyShareEntry{
			Group: uint16(n),
		})
		return nil
	}

	// Heuristic: if data is exactly one KeyShareEntry without outer length
	// prefix, it's ServerHello format. A ServerHello key_share for x25519
	// is 36 bytes (2+2+32); a ClientHello with one x25519 entry is 38
	// bytes (2 total-len + 2+2+32).
	if len(b) >= 4 {
		keyLen := int(binary.BigEndian.Uint16(b[2:4]))
		if 4+keyLen == len(b) {
			ext.Server = true
			ext.Entries = append(ext.Entries, KeyShareEntry{
				Group:       binary.BigEndian.Uint16(b[0:2]),
				KeyExchange: cloneBytes(b[4 : 4+keyLen]),
			})
			return nil
		}
	}

	// ClientHello: 2-byte total length + entries
	bodyLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < bodyLen {
		return fmt.Errorf("key_share: %w", ErrShortBuffer)
	}
	b = b[:bodyLen]

	for len(b) > 0 {
		if len(b) < 4 {
			return fmt.Errorf("key_share: %w", ErrShortBuffer)
		}
		group := binary.BigEndian.Uint16(b[0:2])
		keyLen := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b[4:]) < keyLen {
			return fmt.Errorf("key_share: %w", ErrShortBuffer)
		}
		ext.Entries = append(ext.Entries, KeyShareEntry{
			Group:       group,
			KeyExchange: cloneBytes(b[4 : 4+keyLen]),
		})
		b = b[4+keyLen:]
	}
	return nil
}

type PskKeyExchangeModesExtension struct {
	Modes []uint8
}

func (ext *PskKeyExchangeModesExtension) Type() uint16 {
	return ExtPskKeyExchangeModes
}

func (ext *PskKeyExchangeModesExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(uint8(len(ext.Modes)))
	buf.Write(ext.Modes)
	return buf.Bytes(), nil
}

func (ext *PskKeyExchangeModesExtension) Decode(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("psk_key_exchange_modes: %w", ErrShortBuffer)
	}
	n := int(b[0])
	if len(b[1:]) < n {
		return fmt.Errorf("psk_key_exchange_modes: %w", ErrShortBuffer)
	}
	if n > 0 {
		ext.Modes = make([]uint8, n)
		copy(ext.Modes, b[1:1+n])
	}
	return nil
}

type PreSharedKeyExtension struct {
	Identities       []PskIdentity
	Binders          [][]byte
	SelectedIdentity uint16
	Server           bool
}

type PskIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

func (ext *PreSharedKeyExtension) Type() uint16 {
	return ExtPreSharedKey
}

func (ext *PreSharedKeyExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	if ext.Server {
		binary.Write(buf, binary.BigEndian, ext.SelectedIdentity)
		return buf.Bytes(), nil
	}

	// ClientHello: identities + binders
	identBody := &bytes.Buffer{}
	for _, id := range ext.Identities {
		binary.Write(identBody, binary.BigEndian, uint16(len(id.Identity)))
		identBody.Write(id.Identity)
		binary.Write(identBody, binary.BigEndian, id.ObfuscatedTicketAge)
	}
	binary.Write(buf, binary.BigEndian, uint16(identBody.Len()))
	buf.Write(identBody.Bytes())

	binderBody := &bytes.Buffer{}
	for _, b := range ext.Binders {
		binderBody.WriteByte(uint8(len(b)))
		binderBody.Write(b)
	}
	binary.Write(buf, binary.BigEndian, uint16(binderBody.Len()))
	buf.Write(binderBody.Bytes())

	return buf.Bytes(), nil
}

func (ext *PreSharedKeyExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
	}

	// ServerHello: single uint16 selected identity (2 bytes)
	if len(b) == 2 {
		ext.Server = true
		ext.SelectedIdentity = binary.BigEndian.Uint16(b)
		return nil
	}

	// ClientHello: identities + binders
	identLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < identLen {
		return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
	}
	identData := b[:identLen]
	b = b[identLen:]

	for len(identData) > 0 {
		if len(identData) < 6 {
			return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
		}
		idLen := int(binary.BigEndian.Uint16(identData[:2]))
		identData = identData[2:]
		if len(identData) < idLen+4 {
			return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
		}
		ext.Identities = append(ext.Identities, PskIdentity{
			Identity:            cloneBytes(identData[:idLen]),
			ObfuscatedTicketAge: binary.BigEndian.Uint32(identData[idLen : idLen+4]),
		})
		identData = identData[idLen+4:]
	}

	if len(b) < 2 {
		return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
	}
	binderLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < binderLen {
		return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
	}
	binderData := b[:binderLen]

	for len(binderData) > 0 {
		if len(binderData) < 1 {
			return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
		}
		n := int(binderData[0])
		binderData = binderData[1:]
		if len(binderData) < n {
			return fmt.Errorf("pre_shared_key: %w", ErrShortBuffer)
		}
		ext.Binders = append(ext.Binders, cloneBytes(binderData[:n]))
		binderData = binderData[n:]
	}

	return nil
}

type SignatureAlgorithmsCertExtension struct {
	Algorithms []uint16
}

func (ext *SignatureAlgorithmsCertExtension) Type() uint16 {
	return ExtSignatureAlgorithmsCert
}

func (ext *SignatureAlgorithmsCertExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Algorithms)*2))
	for _, alg := range ext.Algorithms {
		binary.Write(buf, binary.BigEndian, alg)
	}
	return buf.Bytes(), nil
}

func (ext *SignatureAlgorithmsCertExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("signature_algorithms_cert: %w", ErrShortBuffer)
	}
	n := int(binary.BigEndian.Uint16(b))
	if n%2 != 0 {
		return fmt.Errorf("signature_algorithms_cert: odd algorithm list length %d", n)
	}
	if len(b[2:]) < n {
		return fmt.Errorf("signature_algorithms_cert: %w", ErrShortBuffer)
	}
	ext.Algorithms = make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		ext.Algorithms = append(ext.Algorithms, binary.BigEndian.Uint16(b[2+i:]))
	}
	return nil
}

type CookieExtension struct {
	Data []byte
}

func (ext *CookieExtension) Type() uint16 {
	return ExtCookie
}

func (ext *CookieExtension) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Data)))
	buf.Write(ext.Data)
	return buf.Bytes(), nil
}

func (ext *CookieExtension) Decode(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("cookie: %w", ErrShortBuffer)
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b[2:]) < n {
		return fmt.Errorf("cookie: %w", ErrShortBuffer)
	}
	ext.Data = cloneBytes(b[2 : 2+n])
	return nil
}

type EarlyDataExtension struct{}

func (ext *EarlyDataExtension) Type() uint16 {
	return ExtEarlyData
}

func (ext *EarlyDataExtension) Encode() ([]byte, error) {
	return nil, nil
}

func (ext *EarlyDataExtension) Decode(b []byte) error {
	return nil
}

// cloneBytes returns a copy of b, or nil if b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
