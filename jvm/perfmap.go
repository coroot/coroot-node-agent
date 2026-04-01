package jvm

import "bytes"

func IsPerfmapDumpSupported(cmdline []byte) bool {
	return bytes.Contains(cmdline, []byte("-XX:+PreserveFramePointer"))
}
