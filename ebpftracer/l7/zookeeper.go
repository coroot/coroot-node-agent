package l7

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	zkOpCreate          = 1
	zkOpDelete          = 2
	zkOpExists          = 3
	zkOpGetData         = 4
	zkOpSetData         = 5
	zkOpGetAcl          = 6
	zkOpSetAcl          = 7
	zkOpGetChildren     = 8
	zkOpSync            = 9
	zkOpPing            = 11
	zkOpGetChildren2    = 12
	zkOpCheck           = 13
	zkOpMulti           = 14
	zkOpReconfig        = 16
	zkOpCreateContainer = 19
	zkOpCreateTTL       = 21
	zkOpClose           = -11
	zkOpSetAuth         = 100
	zkOpSetWatches      = 101
)

type zkMultiHeader struct {
	Type int32
	Done bool
	Err  int32
}

type zkRequestHeader struct {
	Length uint32
	Xid    int32
	OpType int32
}

func zkParse(r io.Reader, opCode int32) (string, string) {
	switch opCode {
	case zkOpCreate:
		return "create", zkReadString(r)
	case zkOpDelete:
		return "delete", zkReadString(r)
	case zkOpExists:
		return "exists", zkReadString(r)
	case zkOpGetAcl:
		return "getAcl", zkReadString(r)
	case zkOpSetAcl:
		return "setAcl", zkReadString(r)
	case zkOpGetChildren:
		return "getChildren", zkReadString(r)
	case zkOpSync:
		return "sync", zkReadString(r)
	case zkOpPing:
		return "ping", ""
	case zkOpGetChildren2:
		return "getChildren2", zkReadString(r)
	case zkOpCheck:
		return "check", zkReadString(r)
	case zkOpReconfig:
		return "reconfig", ""
	case zkOpCreateContainer:
		return "createContainer", zkReadString(r)
	case zkOpCreateTTL:
		return "createTTL", zkReadString(r)
	case zkOpClose:
		return "close", ""
	case zkOpSetAuth:
		return "setAuth", ""
	case zkOpSetWatches:
		return "setWatches", ""
	case zkOpGetData:
		return "getData", zkReadString(r)
	case zkOpSetData:
		return "setData", zkReadString(r)
	case zkOpMulti:
		h := &zkMultiHeader{}
		if binary.Read(r, binary.BigEndian, h) != nil {
			return "", ""
		}
		op, arg := zkParse(r, h.Type)
		return "multi(" + op + ", ...)", arg
	}
	return "", ""
}

func zkReadString(r io.Reader) string {
	var l uint32
	if binary.Read(r, binary.BigEndian, &l) != nil {
		return ""
	}
	if l > 1024 {
		return ""
	}
	res := make([]byte, l)
	n, err := r.Read(res)
	if err != nil {
		return ""
	}
	if n < int(l) {
		return string(append(res[:n], []byte("...<TRUNCATED>")...))
	}
	return string(res[:n])
}

func ParseZookeeper(payload []byte) (string, string) {
	r := bytes.NewReader(payload)
	h := zkRequestHeader{}
	if err := binary.Read(r, binary.BigEndian, &h); err != nil {
		return "", ""
	}
	return zkParse(r, h.OpType)
}
