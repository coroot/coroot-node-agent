package l7

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
)

func TestParseHttp(t *testing.T) {
	m, p := ParseHttp([]byte(`HEAD /1 HTTP/1.1\nHost: 127.0.0.1\nUser-Agent: curl/8.0.1\nAccept: */*\n\nxzxxxxxxzx`))
	assert.Equal(t, "HEAD", m)
	assert.Equal(t, "/1", p)

	m, p = ParseHttp([]byte(`GET /too-long-uri`))
	assert.Equal(t, "GET", m)
	assert.Equal(t, "/too-long-uri...", p)
}

func Test_parseMemcached(t *testing.T) {
	cmd, items := ParseMemcached(append([]byte(`incr 1111 2222`), '\r', '\n'))
	assert.Equal(t, "incr", cmd)
	assert.Equal(t, []string{"1111"}, items)

	cmd, items = ParseMemcached(append([]byte(`gets 1111 2222 3333`), '\r', '\n'))
	assert.Equal(t, "gets", cmd)
	assert.Equal(t, []string{"1111", "2222", "3333"}, items)
}

func TestParseRedis(t *testing.T) {
	cmd, args := ParseRedis([]byte{
		'*', '3', '\r', '\n',
		'$', '4', '\r', '\n',
		'L', 'L', 'E', 'N', '\r', '\n',
		'$', '6', '\r', '\n',
		'm', 'y', 'l', 'i', 's', 't', '\r', '\n',
		'$', '2', '\r', '\n',
		'x', 'y', '\r', '\n',
	})
	assert.Equal(t, "LLEN", cmd)
	assert.Equal(t, "mylist ...", args)

	cmd, args = ParseRedis([]byte{
		'*', '2', '\r', '\n',
		'$', '8', '\r', '\n',
		'S', 'M', 'E', 'M', 'B', 'E', 'R', 'S', '\r', '\n',
		'$', '6', '\r', '\n',
		'm', 'y', 'l', 'i', 's', 't', '\r', '\n',
	})

	assert.Equal(t, "SMEMBERS", cmd)
	assert.Equal(t, "mylist", args)
}

type mongoHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
	Flags         int32
	SectionKind   uint8
}

func TestParseMongo(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	v := bson.M{"a": "bssssssssssssssssssssssssssssssssssssssssss"}
	data, err := bson.Marshal(v)

	h := mongoHeader{
		MessageLength: 16 + 4 + 1 + int32(len(data)),
		OpCode:        MongoOpMSG,
	}

	assert.NoError(t, binary.Write(buf, binary.LittleEndian, h))
	_, err = buf.Write(data)
	assert.NoError(t, err)

	payload := buf.Bytes()

	assert.Equal(t, `{"a": "bssssssssssssssssssssssssssssssssssssssssss"}`, ParseMongo(payload))
	assert.Equal(t, `<truncated>`, ParseMongo(payload[:20]))

	dataSize := binary.LittleEndian.Uint32(data)

	binary.LittleEndian.PutUint32(payload[mongoHeaderLength+mongoSectionKindLength:], dataSize+1)
	assert.Equal(t, `<truncated>`, ParseMongo(payload))
}
