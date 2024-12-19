package l7

import (
	"bytes"

	"github.com/ClickHouse/ch-go/proto"
)

func ParseClickhouse(payload []byte) string {
	r := proto.NewReader(bytes.NewReader(payload))
	var err error
	if _, err = r.Byte(); err != nil {
		return ""
	}
	if _, err = r.Str(); err != nil {
		return ""
	}
	version := int(proto.FeatureServerQueryTimeInProgress)
	info := proto.ClientInfo{}
	if err = info.DecodeAware(r, version); err != nil {
		return ""
	}
	if info.ProtocolVersion > 0 {
		version = info.ProtocolVersion
	}
	var s proto.Setting

	for {
		if err = s.Decode(r); err != nil {
			return ""
		}
		if s.Key == "" {
			break
		}
	}
	if _, err = r.Str(); err != nil { // inter-server secret
		return ""
	}
	if _, err = r.UVarInt(); err != nil { // stage
		return ""
	}
	if _, err = r.UVarInt(); err != nil { // compression
		return ""
	}
	l, err := r.StrLen()
	if err != nil {
		return ""
	}
	query := make([]byte, min(l, 1024))
	n, _ := r.Read(query)
	query = bytes.TrimSpace(query[:n])
	if len(query) == 0 {
		return ""
	}
	if n < l {
		query = append(query[:len(query)-1], []byte("...<TRUNCATED>")...)
	}
	return string(query)
}
