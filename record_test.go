package dissector

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func makeRecordBytes(contentType uint8, version Version, payload []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(contentType)
	binary.Write(buf, binary.BigEndian, version)
	binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)
	return buf.Bytes()
}

func TestReadRecord(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *Record
		wantErr error
	}{
		{
			name: "handshake record",
			data: makeRecordBytes(Handshake, 0x0303, []byte{0x01, 0x02, 0x03, 0x04}),
			want: &Record{Type: Handshake, Version: 0x0303, Opaque: []byte{0x01, 0x02, 0x03, 0x04}},
		},
		{
			name: "alert record",
			data: makeRecordBytes(EncryptedAlert, 0x0301, []byte{0x02, 0x28}),
			want: &Record{Type: EncryptedAlert, Version: 0x0301, Opaque: []byte{0x02, 0x28}},
		},
		{
			name: "app data record",
			data: makeRecordBytes(AppData, 0x0303, []byte("hello")),
			want: &Record{Type: AppData, Version: 0x0303, Opaque: []byte("hello")},
		},
		{
			name: "change cipher spec",
			data: makeRecordBytes(ChangeCipherSpec, 0x0303, []byte{0x01}),
			want: &Record{Type: ChangeCipherSpec, Version: 0x0303, Opaque: []byte{0x01}},
		},
		{
			name: "heartbeat record",
			data: makeRecordBytes(Heartbeat, 0x0303, []byte{0x01, 0x00, 0x04}),
			want: &Record{Type: Heartbeat, Version: 0x0303, Opaque: []byte{0x01, 0x00, 0x04}},
		},
		{
			name:    "truncated header",
			data:    []byte{0x16, 0x03},
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "truncated payload",
			data:    []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x01},
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "empty reader",
			data:    []byte{},
			wantErr: io.EOF,
		},
		{
			name: "zero-length payload",
			data: makeRecordBytes(Handshake, 0x0303, []byte{}),
			want: &Record{Type: Handshake, Version: 0x0303, Opaque: []byte{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := ReadRecord(bytes.NewReader(tt.data))
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rec.Type != tt.want.Type {
				t.Errorf("Type = %#x, want %#x", rec.Type, tt.want.Type)
			}
			if rec.Version != tt.want.Version {
				t.Errorf("Version = %#x, want %#x", rec.Version, tt.want.Version)
			}
			if !bytes.Equal(rec.Opaque, tt.want.Opaque) {
				t.Errorf("Opaque = %v, want %v", rec.Opaque, tt.want.Opaque)
			}
		})
	}
}

func TestRecordRoundTrip(t *testing.T) {
	original := &Record{
		Type:    Handshake,
		Version: 0x0303,
		Opaque:  []byte{0x01, 0x00, 0x00, 0x30, 0xaa, 0xbb, 0xcc},
	}

	var buf bytes.Buffer
	n, err := original.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Errorf("WriteTo returned n=%d, buf.Len=%d", n, buf.Len())
	}

	parsed, err := ReadRecord(&buf)
	if err != nil {
		t.Fatalf("ReadRecord error: %v", err)
	}
	if parsed.Type != original.Type {
		t.Errorf("Type = %#x, want %#x", parsed.Type, original.Type)
	}
	if parsed.Version != original.Version {
		t.Errorf("Version = %#x, want %#x", parsed.Version, original.Version)
	}
	if !bytes.Equal(parsed.Opaque, original.Opaque) {
		t.Errorf("Opaque = %v, want %v", parsed.Opaque, original.Opaque)
	}
}

func TestConstants(t *testing.T) {
	if RecordHeaderLen != 5 {
		t.Errorf("RecordHeaderLen = %d, want 5", RecordHeaderLen)
	}
}
