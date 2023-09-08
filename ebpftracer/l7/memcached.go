package l7

import (
	"bytes"
	"strings"
)

var (
	space = []byte{' '}
	crlf  = []byte{'\r', '\n'}
)

func ParseMemcached(payload []byte) (string, []string) {
	cmd, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", nil
	}
	command := string(cmd)
	switch command {
	case "set", "add", "cas", "append", "prepend", "replace", "delete", "incr", "decr", "touch":
		if key, _, ok := bytes.Cut(rest, space); ok {
			return command, []string{string(key)}
		}
	case "gat", "gats":
		_, rest, ok = bytes.Cut(rest, space)
		if ok {
			keys, _, ok := bytes.Cut(rest, crlf)
			if ok {
				return command, strings.Split(string(keys), " ")
			}
		}
	case "get", "gets":
		keys, _, ok := bytes.Cut(rest, crlf)
		if ok {
			return command, strings.Split(string(keys), " ")
		}
	}
	return "", nil
}
