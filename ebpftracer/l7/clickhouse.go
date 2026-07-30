package l7

import (
	"bytes"
	"io"
	"unicode/utf8"

	"github.com/ClickHouse/ch-go/proto"
)

// chBoundedReader reads length-prefixed strings without trusting the length
// prefix: ch-go's Reader.Str allocates make([]byte, n) before checking n
// against the available bytes, so a misparse of a truncated capture can claim
// a multi-gigabyte string and the allocation fires even though the read fails.
// No string in the packet can be longer than the captured payload itself.
type chBoundedReader struct {
	r   *proto.Reader
	max int
}

func (b *chBoundedReader) str() (string, error) {
	n, err := b.r.StrLen()
	if err != nil {
		return "", err
	}
	if n > b.max {
		return "", io.ErrUnexpectedEOF
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(b.r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// skipClientInfo mirrors proto.ClientInfo.DecodeAware field-for-field, with
// bounded string reads, and returns the client's protocol version.
func (b *chBoundedReader) skipClientInfo(version int) (int, error) {
	r := b.r
	kind, err := r.UInt8()
	if err != nil {
		return 0, err
	}
	if !proto.ClientQueryKind(kind).IsAClientQueryKind() {
		return 0, io.ErrUnexpectedEOF
	}
	for i := 0; i < 3; i++ { // initial user, initial query id, initial address
		if _, err := b.str(); err != nil {
			return 0, err
		}
	}
	if proto.FeatureQueryStartTime.In(version) {
		if _, err := r.Int64(); err != nil {
			return 0, err
		}
	}
	iface, err := r.UInt8()
	if err != nil {
		return 0, err
	}
	if proto.Interface(iface) != proto.InterfaceTCP {
		return 0, io.ErrUnexpectedEOF
	}
	for i := 0; i < 3; i++ { // os user, client hostname, client name
		if _, err := b.str(); err != nil {
			return 0, err
		}
	}
	for i := 0; i < 2; i++ { // major, minor version
		if _, err := r.Int(); err != nil {
			return 0, err
		}
	}
	protocolVersion, err := r.Int()
	if err != nil {
		return 0, err
	}
	if proto.FeatureQuotaKeyInClientInfo.In(version) {
		if _, err := b.str(); err != nil {
			return 0, err
		}
	}
	if proto.FeatureDistributedDepth.In(version) {
		if _, err := r.Int(); err != nil {
			return 0, err
		}
	}
	if proto.FeatureVersionPatch.In(version) {
		if _, err := r.Int(); err != nil {
			return 0, err
		}
	}
	if proto.FeatureOpenTelemetry.In(version) {
		hasTrace, err := r.Bool()
		if err != nil {
			return 0, err
		}
		if hasTrace {
			if _, err := r.ReadRaw(16); err != nil { // trace id
				return 0, err
			}
			if _, err := r.ReadRaw(8); err != nil { // span id
				return 0, err
			}
			if _, err := b.str(); err != nil { // trace state
				return 0, err
			}
			if _, err := r.Byte(); err != nil { // trace flags
				return 0, err
			}
		}
	}
	if proto.FeatureParallelReplicas.In(version) {
		for i := 0; i < 3; i++ { // collaborate with initiator, participating replicas, current replica
			if _, err := r.Int(); err != nil {
				return 0, err
			}
		}
	}
	return protocolVersion, nil
}

func (b *chBoundedReader) skipSettings() error {
	for {
		key, err := b.str()
		if err != nil {
			return err
		}
		if key == "" {
			return nil
		}
		if _, err := b.r.UVarInt(); err != nil {
			return err
		}
		if _, err := b.str(); err != nil {
			return err
		}
	}
}

func ParseClickhouse(payload []byte) (query string) {
	defer func() {
		if recover() != nil {
			query = ""
		}
	}()
	r := proto.NewReader(bytes.NewReader(payload))
	b := &chBoundedReader{r: r, max: len(payload)}
	var err error
	if _, err = r.Byte(); err != nil {
		return ""
	}
	if _, err = b.str(); err != nil { // query id
		return ""
	}
	version := int(proto.FeatureServerQueryTimeInProgress)
	protocolVersion, err := b.skipClientInfo(version)
	if err != nil {
		return ""
	}
	if protocolVersion > 0 {
		if protocolVersion > version {
			return ""
		}
		version = protocolVersion
	}
	if err = b.skipSettings(); err != nil {
		return ""
	}
	if _, err = b.str(); err != nil { // inter-server secret
		return ""
	}
	if stage, err := r.UVarInt(); err != nil { // stage
		return ""
	} else if stage > 2 { // invalid stage
		return ""
	}
	if c, err := r.UVarInt(); err != nil { // compression
		return ""
	} else if c > 1 { // invalid compression
		return ""
	}
	l, err := r.StrLen()
	if err != nil {
		return ""
	}
	buf := make([]byte, min(l, 1024))
	n, _ := r.Read(buf)
	buf = bytes.TrimSpace(buf[:n])
	if len(buf) == 0 {
		return ""
	}
	if !utf8.Valid(buf) { // not a real query: misclassified or corrupted payload
		return ""
	}
	if n < l {
		buf = append(buf[:len(buf)-1], []byte("...<TRUNCATED>")...)
	}
	return string(buf)
}
