package l7

import (
	"bytes"
)

// https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Syntax
func ParseHttp(payload []byte) (string, string, string) {
	method, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", "", ""
	}
	if !isHttpMethod(string(method)) {
		return "", "", ""
	}
	uri, _, ok := bytes.Cut(rest, space)
	if !ok {
		uri = append(uri, []byte("...")...)
	}
	path, _, _ := bytes.Cut(uri, []byte{'?'})
	return string(method), string(uri), string(path)
}
