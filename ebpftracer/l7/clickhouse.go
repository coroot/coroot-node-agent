package l7

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

const (
	chLatestSupportedProtocolVersion = 54460 // DBMS_MIN_PROTOCOL_VERSION_WITH_SERVER_QUERY_TIME_IN_PROGRESS
	chInterfaceTCP                   = 1
	chMaxQuerySize                   = 1024
)

type chReader struct {
	data []byte
	off  int
}

func (r *chReader) uvarint() (uint64, bool) {
	if r.off >= len(r.data) {
		return 0, false
	}
	v, n := binary.Uvarint(r.data[r.off:])
	if n <= 0 {
		return 0, false
	}
	r.off += n
	return v, true
}

func (r *chReader) byte() (byte, bool) {
	if r.off >= len(r.data) {
		return 0, false
	}
	b := r.data[r.off]
	r.off++
	return b, true
}

func (r *chReader) skip(n int) bool {
	if n < 0 || n > len(r.data)-r.off {
		return false
	}
	r.off += n
	return true
}

func (r *chReader) skipStr() bool {
	l, ok := r.uvarint()
	return ok && l <= uint64(len(r.data)-r.off) && r.skip(int(l))
}

func (r *chReader) skipStrings(n int) bool {
	for i := 0; i < n; i++ {
		if !r.skipStr() {
			return false
		}
	}
	return true
}

func (r *chReader) skipUvarints(n int) bool {
	for i := 0; i < n; i++ {
		if _, ok := r.uvarint(); !ok {
			return false
		}
	}
	return true
}

func ParseClickhouse(payload []byte) string {
	r := &chReader{data: payload}
	if _, ok := r.byte(); !ok { // packet type (Query)
		return ""
	}
	if !r.skipStr() { // query id
		return ""
	}

	if kind, ok := r.byte(); !ok || kind < 1 || kind > 2 { // initial or secondary query
		return ""
	}
	if !r.skipStrings(3) { // initial user, initial query id, initial address
		return ""
	}
	if !r.skip(8) { // initial query start time
		return ""
	}
	if iface, ok := r.byte(); !ok || iface != chInterfaceTCP {
		return ""
	}
	if !r.skipStrings(3) { // os user, client hostname, client name
		return ""
	}
	if !r.skipUvarints(2) { // client version major, minor
		return ""
	}
	if v, ok := r.uvarint(); !ok || v > chLatestSupportedProtocolVersion {
		return ""
	}
	if !r.skipStr() { // quota key
		return ""
	}
	if !r.skipUvarints(2) { // distributed depth, client version patch
		return ""
	}
	if hasTrace, ok := r.byte(); !ok { // OpenTelemetry context
		return ""
	} else if hasTrace == 1 {
		if !r.skip(16 + 8) { // trace id, span id
			return ""
		}
		if !r.skipStr() { // trace state
			return ""
		}
		if _, ok = r.byte(); !ok { // trace flags
			return ""
		}
	}
	if !r.skipUvarints(3) { // collaborate with initiator, count of participating replicas, number of the current replica
		return ""
	}

	for { // settings
		l, ok := r.uvarint() // key
		if !ok || l > uint64(len(r.data)-r.off) || !r.skip(int(l)) {
			return ""
		}
		if l == 0 {
			break
		}
		if _, ok = r.uvarint(); !ok { // flags
			return ""
		}
		if !r.skipStr() { // value
			return ""
		}
	}
	if !r.skipStr() { // inter-server secret
		return ""
	}
	if stage, ok := r.uvarint(); !ok || stage > 2 {
		return ""
	}
	if compression, ok := r.uvarint(); !ok || compression > 1 {
		return ""
	}

	l, ok := r.uvarint() // query size
	if !ok || r.off > len(r.data) {
		return ""
	}
	query := r.data[r.off:]
	if uint64(len(query)) > l {
		query = query[:l]
	}
	if len(query) > chMaxQuerySize {
		query = query[:chMaxQuerySize]
	}
	truncated := uint64(len(query)) < l
	query = bytes.TrimSpace(query)
	if len(query) == 0 {
		return ""
	}
	if !utf8.Valid(query) { // not a real query: misclassified or corrupted payload
		return ""
	}
	if truncated {
		query = query[:len(query)-1]
		for len(query) > 0 { // don't leave a partial multi-byte character at the end
			if r, size := utf8.DecodeLastRune(query); r != utf8.RuneError || size > 1 {
				break
			}
			query = query[:len(query)-1]
		}
		if len(query) == 0 {
			return ""
		}
		return string(query) + "...<TRUNCATED>"
	}
	return string(query)
}
