package dissector

import (
	"crypto/tls"
	"io"
)

type ClientHelloInfo struct {
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	SupportedProtos    []string
	SupportedVersions  []uint16
	ServerName         string
}

func ParseClientHello(r io.Reader) (*ClientHelloInfo, error) {
	record, err := ReadRecord(r)
	if err != nil {
		return nil, err
	}
	if record.Type != Handshake {
		return nil, ErrBadType
	}

	msg := &ClientHelloMsg{}
	if err := msg.Decode(record.Opaque); err != nil {
		return nil, err
	}

	info := &ClientHelloInfo{
		SessionID:          msg.SessionID,
		CipherSuites:       msg.CipherSuites,
		CompressionMethods: msg.CompressionMethods,
	}

	for _, ext := range msg.Extensions {
		switch ext.Type() {
		case ExtServerName:
			sniExt := ext.(*ServerNameExtension)
			info.ServerName = sniExt.Name
		case ExtSupportedVersions:
			verExt := ext.(*SupportedVersionsExtension)
			info.SupportedVersions = verExt.Versions
		case ExtALPN:
			alpnExt := ext.(*ALPNExtension)
			info.SupportedProtos = alpnExt.Protos
		}
	}

	return info, nil
}

type ServerHelloInfo struct {
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Proto             string
	Version           uint16
}

func ParseServerHello(r io.Reader) (*ServerHelloInfo, error) {
	record, err := ReadRecord(r)
	if err != nil {
		return nil, err
	}
	if record.Type != Handshake {
		return nil, ErrBadType
	}

	msg := &ServerHelloMsg{}
	if err := msg.Decode(record.Opaque); err != nil {
		return nil, err
	}

	info := &ServerHelloInfo{
		SessionID:         msg.SessionID,
		CipherSuite:       msg.CipherSuite,
		CompressionMethod: msg.CompressionMethod,
		Version:           tls.VersionTLS12,
	}

	for _, ext := range msg.Extensions {
		switch ext.Type() {
		case ExtSupportedVersions:
			verExt := ext.(*SupportedVersionsExtension)
			if len(verExt.Versions) > 0 {
				info.Version = verExt.Versions[0]
			}
		case ExtALPN:
			alpnExt := ext.(*ALPNExtension)
			if len(alpnExt.Protos) > 0 {
				info.Proto = alpnExt.Protos[0]
			}
		}
	}

	return info, nil
}
