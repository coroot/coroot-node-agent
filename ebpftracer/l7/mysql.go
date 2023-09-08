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
	cmd := payload[4]
	readQuery := func() (query string) {
		to := mysqlMsgHeaderSize + msgSize
		partial := false
		if to > payloadSize {
			to = payloadSize
			partial = true
		}
		query = string(payload[mysqlMsgHeaderSize+1 : to])
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
		return readQuery()
	case MysqlComStmtExecute:
		statementIdStr := readStatementId()
		statement, ok := p.preparedStatements[statementIdStr]
		if !ok {
			statement = fmt.Sprintf(`EXECUTE %s /* unknown */`, statementIdStr)
		}
		return statement
	case MysqlComStmtPrepare:
		query := readQuery()
		statementIdStr := strconv.FormatUint(uint64(statementId), 10)
		p.preparedStatements[statementIdStr] = query
		return fmt.Sprintf("PREPARE %s FROM %s", statementIdStr, query)
	case MysqlComStmtClose:
		statementIdStr := readStatementId()
		delete(p.preparedStatements, statementIdStr)
	}
	return ""
}
