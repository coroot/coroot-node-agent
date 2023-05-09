package tracing

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
)

func Test_parseHttp(t *testing.T) {
	m, p := parseHttp([]byte(`HEAD /1 HTTP/1.1\nHost: 127.0.0.1\nUser-Agent: curl/8.0.1\nAccept: */*\n\nxzxxxxxxzx`))
	assert.Equal(t, "HEAD", m)
	assert.Equal(t, "/1", p)

	m, p = parseHttp([]byte(`GET /too-long-uri`))
	assert.Equal(t, "GET", m)
	assert.Equal(t, "/too-long-uri...", p)
}

func Test_parseMemcached(t *testing.T) {
	cmd, items := parseMemcached(append([]byte(`incr 1111 2222`), '\r', '\n'))
	assert.Equal(t, "incr", cmd)
	assert.Equal(t, []string{"1111"}, items)

	cmd, items = parseMemcached(append([]byte(`gets 1111 2222 3333`), '\r', '\n'))
	assert.Equal(t, "gets", cmd)
	assert.Equal(t, []string{"1111", "2222", "3333"}, items)
}

func Test_parseRedis(t *testing.T) {
	cmd, args := parseRedis([]byte{
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

	cmd, args = parseRedis([]byte{
		'*', '2', '\r', '\n',
		'$', '8', '\r', '\n',
		'S', 'M', 'E', 'M', 'B', 'E', 'R', 'S', '\r', '\n',
		'$', '6', '\r', '\n',
		'm', 'y', 'l', 'i', 's', 't', '\r', '\n',
	})

	assert.Equal(t, "SMEMBERS", cmd)
	assert.Equal(t, "mylist", args)
}

func Test_parseMongo(t *testing.T) {
	v := bson.M{"a": "bssssssssssssssssssssssssssssssssssssssssss"}
	buf := make([]byte, 1024)
	data, err := bson.Marshal(v)
	assert.NoError(t, err)
	copy(buf, data)
	assert.Equal(t, `{"a": "bssssssssssssssssssssssssssssssssssssssssss"}`, bsonToString(bytes.NewReader(buf)))
	assert.Equal(t, `<truncated>`, bsonToString(bytes.NewReader(buf[:20])))
}
