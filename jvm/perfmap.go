package jvm

import (
	"bytes"
	"fmt"
)

func DumpPerfmap(pid uint32) error {
	j, err := Dial(pid)
	if err != nil {
		return fmt.Errorf("failed to attach to JVM %d: %w", pid, err)
	}
	defer j.Close()
	if err = j.DumpPerfmap(); err != nil {
		return fmt.Errorf("failed to dump perfmap of JVM %d: %w", pid, err)
	}
	return nil
}

func IsPerfmapDumpSupported(cmdline []byte) bool {
	if !bytes.Contains(cmdline, []byte("-XX:+PreserveFramePointer")) {
		return false
	}
	return true
}
