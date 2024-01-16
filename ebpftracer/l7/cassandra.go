package l7

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type CassandraParser struct {
	preparedStatements map[string]string
}

func NewCassandraParser() *CassandraParser {
	return &CassandraParser{preparedStatements: map[string]string{}}
}

func (p *CassandraParser) Parse(payload []byte, statementId, method uint32) string {
	opcode := payload[4]
	query := p.ParseMessages(int(opcode), payload[9:])
	if method == uint32(MethodStatementPrepare) {
		id := strconv.FormatUint(uint64(statementId), 10)
		p.preparedStatements[id] = query
		return fmt.Sprintf("PREPARE %s FROM %s", id, query)
	}
	return query
}

func (p *CassandraParser) ParseMessages(opcode int, messages []byte) string {
	// klog.Infof("ParseMessages: opcode=%v, messages=%v", opcode, messages)
	switch opcode {
	case 7: // query
		return p.ParseQuery(messages)
	case 9: // prepare
		return p.ParsePrepare(messages)
	case 10: // execute
		return p.ParseExecute(messages)
	}
	return ""
}

func (p *CassandraParser) ParseQuery(messages []byte) string {
	query := messages[0:4]
	length := binary.BigEndian.Uint32(query)
	query = messages[4 : 4+length]
	return string(query)
}

func (p *CassandraParser) ParsePrepare(messages []byte) string {
	query := messages[0:4]
	length := binary.BigEndian.Uint32(query)
	query = messages[4 : 4+length]
	return string(query)
}

func (p *CassandraParser) ParseExecute(messages []byte) string {
	// next length bytes are the id but we just get the first 4 bytes
	id := messages[2 : 2+4]
	idstr := strconv.Itoa(int(binary.LittleEndian.Uint32(id)))
	if query, ok := p.preparedStatements[idstr]; ok {
		return query
	}
	return fmt.Sprintf(`EXECUTE %s /* unknown */`, idstr)
}
