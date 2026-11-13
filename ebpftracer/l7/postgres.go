package l7

import (
	"bytes"
	"fmt"
)

const (
	PostgresFrameQuery byte = 'Q'
	PostgresFrameBind  byte = 'B'
	PostgresFrameParse byte = 'P'
	PostgresFrameClose byte = 'C'
)

type PostgresParser struct {
	preparedStatements map[string]string
}

func NewPostgresParser() *PostgresParser {
	return &PostgresParser{preparedStatements: map[string]string{}}
}

func (p *PostgresParser) Parse(payload []byte) string {
	l := len(payload)
	if l < 5 {
		return ""
	}
	cmd := payload[0]
	switch cmd {
	case PostgresFrameQuery:
		q, _, ok := bytes.Cut(payload[5:], []byte{0})
		return payloadString(q, !ok)
	case PostgresFrameBind:
		_, rest, ok := bytes.Cut(payload[5:], []byte{0})
		if !ok {
			return ""
		}
		preparedStatementName, _, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return ""
		}
		preparedStatementNameStr := string(preparedStatementName)
		statement, ok := p.preparedStatements[preparedStatementNameStr]
		if !ok {
			statement = fmt.Sprintf(`EXECUTE %s /* unknown */`, preparedStatementNameStr)
		}
		return statement
	case PostgresFrameParse:
		preparedStatementName, rest, ok := bytes.Cut(payload[5:], []byte{0})
		if !ok {
			return ""
		}
		q, _, ok := bytes.Cut(rest, []byte{0})
		query := payloadString(q, !ok)
		preparedStatementNameStr := string(preparedStatementName)
		p.preparedStatements[preparedStatementNameStr] = query
		return fmt.Sprintf("PREPARE %s AS %s", preparedStatementNameStr, query)
	case PostgresFrameClose:
		if l < 7 {
			return ""
		}
		if payload[5] != 'S' {
			return ""
		}
		preparedStatementName, _, ok := bytes.Cut(payload[6:], []byte{0})
		if !ok {
			return ""
		}
		delete(p.preparedStatements, string(preparedStatementName))
	}
	return ""
}
