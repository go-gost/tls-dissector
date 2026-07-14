package dissector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	RecordHeaderLen    = 5
	MaxPlaintextLength = 16384 // 2^14, per TLS spec
)

// record content type
const (
	ChangeCipherSpec = 0x14
	EncryptedAlert   = 0x15
	Handshake        = 0x16
	AppData          = 0x17
	Heartbeat        = 0x18
)

var (
	ErrBadType = errors.New("bad type")
	ErrAlert   = errors.New("alert")
)

type Version uint16

const (
	VersionSSL30 Version = 0x0300
	VersionTLS10 Version = 0x0301
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)

type Record struct {
	Type    uint8
	Version Version
	Opaque  []byte
}

func ReadRecord(r io.Reader) (*Record, error) {
	record := &Record{}
	if _, err := record.ReadFrom(r); err != nil {
		return nil, err
	}
	return record, nil
}

func (rec *Record) ReadFrom(r io.Reader) (n int64, err error) {
	var b [RecordHeaderLen]byte
	nn, err := io.ReadFull(r, b[:])
	n += int64(nn)
	if err != nil {
		return
	}
	rec.Type = b[0]
	rec.Version = Version(binary.BigEndian.Uint16(b[1:3]))
	length := int(binary.BigEndian.Uint16(b[3:5]))
	if length > MaxPlaintextLength {
		return 0, fmt.Errorf("record length %d exceeds max %d", length, MaxPlaintextLength)
	}
	rec.Opaque = make([]byte, length)
	nn, err = io.ReadFull(r, rec.Opaque)
	n += int64(nn)
	return
}

func (rec *Record) WriteTo(w io.Writer) (n int64, err error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(rec.Type)
	binary.Write(buf, binary.BigEndian, rec.Version)
	binary.Write(buf, binary.BigEndian, uint16(len(rec.Opaque)))
	buf.Write(rec.Opaque)
	return buf.WriteTo(w)
}
