package l7

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

const (
	MysqlComQuery       = 3
	MysqlComStmtPrepare = 0x16
	MysqlComStmtExecute = 0x17
	MysqlComStmtClose   = 0x19

	mysqlMsgHeaderSize = 4
)

type MysqlParser struct {
	preparedStatements map[string]string
}

func NewMysqlParser() *MysqlParser {
	return &MysqlParser{preparedStatements: map[string]string{}}
}

func (p *MysqlParser) Parse(payload []byte, statementId uint32) string {
	payloadSize := len(payload)
	if payloadSize < mysqlMsgHeaderSize+5 {
		return ""
	}
	msgSize := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	if msgSize < 1 {
		return ""
	}
	cmd := payload[4]
	readQuery := func(withQueryAttributes bool) (query string) {
		to := mysqlMsgHeaderSize + msgSize
		partial := false
		if to > payloadSize {
			to = payloadSize
			partial = true
		}
		body := payload[mysqlMsgHeaderSize+1 : to]
		if withQueryAttributes {
			if n, ok := skipQueryAttributes(body); ok {
				body = body[n:]
			}
		}
		query = string(body)
		if partial {
			query += "..."
		}
		return query
	}
	readStatementId := func() string {
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(payload[mysqlMsgHeaderSize+1:])), 10)
	}

	switch cmd {
	case MysqlComQuery:
		return readQuery(true)
	case MysqlComStmtExecute:
		statementIdStr := readStatementId()
		statement, ok := p.preparedStatements[statementIdStr]
		if !ok {
			statement = fmt.Sprintf(`EXECUTE %s /* unknown */`, statementIdStr)
		}
		return statement
	case MysqlComStmtPrepare:
		query := readQuery(false)
		statementIdStr := strconv.FormatUint(uint64(statementId), 10)
		p.preparedStatements[statementIdStr] = query
		return fmt.Sprintf("PREPARE %s FROM %s", statementIdStr, query)
	case MysqlComStmtClose:
		statementIdStr := readStatementId()
		delete(p.preparedStatements, statementIdStr)
	}
	return ""
}

func skipQueryAttributes(b []byte) (int, bool) {
	r := &byteReader{data: b}
	count, ok := r.lenencInt()
	setCount, ok2 := r.lenencInt()
	if !ok || !ok2 || setCount != 1 {
		return 0, false
	}
	if count == 0 {
		return r.off, true
	}
	if count > (len(b)-r.off)/3 {
		return 0, false
	}
	nullBitmap, ok := r.bytes((count + 7) / 8)
	if !ok {
		return 0, false
	}
	if flag, ok := r.byte(); !ok || flag != 1 {
		return 0, false
	}
	types := make([]byte, count)
	for i := range types {
		typ, ok := r.byte()
		if !ok || !r.skip(1) || !r.skipLenencStr() {
			return 0, false
		}
		types[i] = typ
	}
	for i, typ := range types {
		if nullBitmap[i/8]&(1<<(i%8)) != 0 {
			continue
		}
		switch typ {
		case 0x01: // TINY
			ok = r.skip(1)
		case 0x02, 0x0d: // SHORT, YEAR
			ok = r.skip(2)
		case 0x03, 0x04, 0x09: // LONG, FLOAT, INT24
			ok = r.skip(4)
		case 0x05, 0x08: // DOUBLE, LONGLONG
			ok = r.skip(8)
		default: // strings, blobs, decimals, JSON, DATE/DATETIME/TIMESTAMP/TIME are all length-prefixed
			ok = r.skipLenencStr()
		}
		if !ok {
			return 0, false
		}
	}
	return r.off, true
}

func (r *byteReader) lenencInt() (int, bool) {
	h, ok := r.byte()
	if !ok {
		return 0, false
	}
	var size int
	switch h {
	case 0xfc:
		size = 2
	case 0xfd:
		size = 3
	case 0xfe:
		size = 8
	case 0xfb, 0xff: // NULL and error markers
		return 0, false
	default:
		return int(h), true
	}
	raw, ok := r.bytes(size)
	if !ok {
		return 0, false
	}
	v := 0
	for i, c := range raw {
		v |= int(c) << (8 * i)
	}
	return v, v >= 0
}

func (r *byteReader) skipLenencStr() bool {
	l, ok := r.lenencInt()
	return ok && r.skip(l)
}
