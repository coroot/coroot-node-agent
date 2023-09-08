package l7

import (
	"bytes"
	"strconv"
)

func ParseRedis(payload []byte) (cmd string, args string) {
	var v, rest []byte
	var ok bool
	v, rest, ok = bytes.Cut(payload, crlf)
	if !ok || !bytes.HasPrefix(v, []byte("*")) {
		return
	}
	arrayLen, err := strconv.ParseUint(string(v[1:]), 10, 32)
	if err != nil {
		return
	}
	readString := func() string {
		v, rest, ok = bytes.Cut(rest, crlf)
		if !ok || !bytes.HasPrefix(v, []byte("$")) {
			return ""
		}
		v, rest, ok = bytes.Cut(rest, crlf)
		if ok {
			return string(v)
		}
		return ""
	}
	cmd = readString()
	if cmd == "" {
		return
	}
	if arrayLen > 1 {
		args = readString()
		if arrayLen > 2 {
			args += " ..."
		}
	}
	return
}
