package l7

import (
	"bytes"
)

func ParseHttp(payload []byte) (string, string) {
	method, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", ""
	}
	if !isHttpMethod(string(method)) {
		return "", ""
	}
	uri, _, ok := bytes.Cut(rest, space)
	return string(method), payloadString(uri, !ok)
}
