package proc

import "bytes"

func IsJvm(cmdline []byte) bool {
	idx := bytes.Index(cmdline, []byte{0})
	if idx < 0 {
		return false
	}
	return bytes.HasSuffix(cmdline[:idx], []byte("java"))
}
