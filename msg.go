package dissector

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	handshakeHeaderLen = 4
)

const (
	HelloRequest uint8 = 0
	ClientHello  uint8 = 1
	ServerHello  uint8 = 2
)

type Random struct {
	Time   uint32
	Opaque [28]byte
}

type ClientHelloMsg struct {
	Version            Version
	Random             Random
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension
}

func (m *ClientHelloMsg) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.WriteTo(buf); err != nil {
		return
	}
	data = buf.Bytes()
	return
}

func (m *ClientHelloMsg) Decode(data []byte) (err error) {
	_, err = m.ReadFrom(bytes.NewReader(data))
	return
}

func (m *ClientHelloMsg) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, handshakeHeaderLen)
	nn, err := io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}

	if b[0] != ClientHello {
		err = ErrBadType
		return
	}

	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length < 34 { // length of version + random
		err = fmt.Errorf("bad length, need at least 34 bytes, got %d", length)
		return
	}

	b = make([]byte, length)
	nn, err = io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}
	m.Version = Version(binary.BigEndian.Uint16(b[:2]))
	if m.Version < tls.VersionTLS10 || m.Version > tls.VersionTLS13 {
		err = fmt.Errorf("bad version %x", m.Version)
		return
	}

	pos := 2
	m.Random.Time = binary.BigEndian.Uint32(b[pos : pos+4])
	pos += 4
	copy(m.Random.Opaque[:], b[pos:pos+28])
	pos += 28

	nn, err = m.readSession(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	nn, err = m.readCipherSuites(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	nn, err = m.readCompressionMethods(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	_, err = m.readExtensions(b[pos:])
	if err != nil {
		return
	}
	// pos += nn

	return
}

func (m *ClientHelloMsg) readSession(b []byte) (n int, err error) {
	if len(b) == 0 {
		err = fmt.Errorf("bad length: data too short for session")
		return
	}

	nlen := int(b[0])
	n++
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for session")
	}
	if nlen > 0 && n+nlen <= len(b) {
		m.SessionID = make([]byte, nlen)
		copy(m.SessionID, b[n:n+nlen])
		n += nlen
	}

	return
}

func (m *ClientHelloMsg) readCipherSuites(b []byte) (n int, err error) {
	if len(b) < 2 {
		err = fmt.Errorf("bad length: data too short for cipher suites")
		return
	}

	nlen := int(binary.BigEndian.Uint16(b[:2]))
	n += 2
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for cipher suites")
	}
	for i := 0; i < nlen/2; i++ {
		m.CipherSuites = append(m.CipherSuites, binary.BigEndian.Uint16(b[n:n+2]))
		n += 2
	}

	return
}

func (m *ClientHelloMsg) readCompressionMethods(b []byte) (n int, err error) {
	if len(b) == 0 {
		err = fmt.Errorf("bad length: data too short for compression methods")
		return
	}
	nlen := int(b[0])
	n++
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for compression methods")
	}
	for i := 0; i < nlen; i++ {
		m.CompressionMethods = append(m.CompressionMethods, b[n])
		n++
	}
	return
}

func (m *ClientHelloMsg) readExtensions(b []byte) (n int, err error) {
	if len(b) < 2 {
		err = fmt.Errorf("bad length: data too short for extensions")
		return
	}
	nlen := int(binary.BigEndian.Uint16(b[:2]))
	n += 2
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for extensions")
		return
	}

	m.Extensions, err = readExtensions(b[n : n+nlen])
	n += nlen

	return
}

func (m *ClientHelloMsg) WriteTo(w io.Writer) (n int64, err error) {
	buf := &bytes.Buffer{}

	buf.WriteByte(ClientHello)
	buf.Write([]byte{0, 0, 0}) // placeholder for payload length
	binary.Write(buf, binary.BigEndian, m.Version)
	pos := 6

	binary.Write(buf, binary.BigEndian, m.Random.Time)
	buf.Write(m.Random.Opaque[:])
	pos += 32

	buf.WriteByte(byte(len(m.SessionID)))
	buf.Write(m.SessionID)
	pos += (1 + len(m.SessionID))

	binary.Write(buf, binary.BigEndian, uint16(len(m.CipherSuites)*2))
	for _, cs := range m.CipherSuites {
		binary.Write(buf, binary.BigEndian, cs)
	}
	pos += (2 + len(m.CipherSuites)*2)

	buf.WriteByte(byte(len(m.CompressionMethods)))
	for _, cm := range m.CompressionMethods {
		buf.WriteByte(byte(cm))
	}
	pos += (1 + len(m.CompressionMethods))
	buf.Write([]byte{0, 0}) // placeholder for extensions length

	extLen := 0
	for _, ext := range m.Extensions {
		var b []byte
		b, err = ext.Encode()
		if err != nil {
			return
		}
		binary.Write(buf, binary.BigEndian, ext.Type())
		binary.Write(buf, binary.BigEndian, uint16(len(b)))
		extLen += extensionHeaderLen

		nn, _ := buf.Write(b)
		extLen += nn
	}

	b := buf.Bytes()
	plen := len(b) - handshakeHeaderLen
	b[1], b[2], b[3] = byte((plen>>16)&0xFF), byte((plen>>8)&0xFF), byte(plen&0xFF) // payload length
	b[pos], b[pos+1] = byte((extLen>>8)&0xFF), byte(extLen&0xFF)                    // extensions length

	nn, err := w.Write(b)
	n = int64(nn)
	return
}

type ServerHelloMsg struct {
	Version           Version
	Random            Random
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []Extension
}

func (m *ServerHelloMsg) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.WriteTo(buf); err != nil {
		return
	}
	data = buf.Bytes()
	return
}

func (m *ServerHelloMsg) Decode(data []byte) (err error) {
	_, err = m.ReadFrom(bytes.NewReader(data))
	return
}

func (m *ServerHelloMsg) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, handshakeHeaderLen)
	nn, err := io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}

	if b[0] != ServerHello {
		err = ErrBadType
		return
	}

	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length < 34 { // length of version + random
		err = fmt.Errorf("bad length, need at least 34 bytes, got %d", length)
		return
	}

	b = make([]byte, length)
	nn, err = io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}
	m.Version = Version(binary.BigEndian.Uint16(b[:2]))
	if m.Version < tls.VersionTLS10 || m.Version > tls.VersionTLS13 {
		err = fmt.Errorf("bad version %x", m.Version)
		return
	}

	pos := 2
	m.Random.Time = binary.BigEndian.Uint32(b[pos : pos+4])
	pos += 4
	copy(m.Random.Opaque[:], b[pos:pos+28])
	pos += 28

	nn, err = m.readSession(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	m.CipherSuite = binary.BigEndian.Uint16(b[pos : pos+2])
	pos += 2

	m.CompressionMethod = b[pos]
	pos++

	_, err = m.readExtensions(b[pos:])
	if err != nil {
		return
	}
	// pos += nn

	return
}

func (m *ServerHelloMsg) readSession(b []byte) (n int, err error) {
	if len(b) == 0 {
		err = fmt.Errorf("bad length: data too short for session")
		return
	}

	nlen := int(b[0])
	n++
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for session")
	}
	if nlen > 0 && n+nlen <= len(b) {
		m.SessionID = make([]byte, nlen)
		copy(m.SessionID, b[n:n+nlen])
		n += nlen
	}

	return
}

func (m *ServerHelloMsg) readExtensions(b []byte) (n int, err error) {
	if len(b) < 2 {
		err = fmt.Errorf("bad length: data too short for extensions")
		return
	}
	nlen := int(binary.BigEndian.Uint16(b[:2]))
	n += 2
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for extensions")
		return
	}

	m.Extensions, err = readExtensions(b[n : n+nlen])
	n += nlen

	return
}

func (m *ServerHelloMsg) WriteTo(w io.Writer) (n int64, err error) {
	buf := &bytes.Buffer{}

	buf.WriteByte(ServerHello)
	buf.Write([]byte{0, 0, 0}) // placeholder for payload length
	binary.Write(buf, binary.BigEndian, m.Version)
	pos := 6

	binary.Write(buf, binary.BigEndian, m.Random.Time)
	buf.Write(m.Random.Opaque[:])
	pos += 32

	buf.WriteByte(byte(len(m.SessionID)))
	buf.Write(m.SessionID)
	pos += (1 + len(m.SessionID))

	binary.Write(buf, binary.BigEndian, uint16(m.CipherSuite))
	pos += 2

	buf.WriteByte(m.CompressionMethod)
	pos++

	buf.Write([]byte{0, 0}) // placeholder for extensions length
	extLen := 0
	for _, ext := range m.Extensions {
		var b []byte
		b, err = ext.Encode()
		if err != nil {
			return
		}
		binary.Write(buf, binary.BigEndian, ext.Type())
		binary.Write(buf, binary.BigEndian, uint16(len(b)))
		extLen += extensionHeaderLen

		nn, _ := buf.Write(b)
		extLen += nn
	}

	b := buf.Bytes()
	plen := len(b) - handshakeHeaderLen
	b[1], b[2], b[3] = byte((plen>>16)&0xFF), byte((plen>>8)&0xFF), byte(plen&0xFF) // payload length
	b[pos], b[pos+1] = byte((extLen>>8)&0xFF), byte(extLen&0xFF)                    // extensions length

	nn, err := w.Write(b)
	n = int64(nn)
	return
}
