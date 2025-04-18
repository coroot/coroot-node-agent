package jvm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/coroot/coroot-node-agent/proc"
)

const (
	connectionTimeout = 5 * time.Second
	requestTimeout    = 5 * time.Second
)

type JVM struct {
	conn net.Conn
}

func Dial(pid uint32) (*JVM, error) {
	nsPid, err := proc.GetNsPid(pid)
	if err != nil {
		return nil, err
	}
	sockPath := proc.Path(pid, fmt.Sprintf("root/tmp/.java_pid%d", nsPid))

	attachFiles := []string{
		proc.Path(pid, fmt.Sprintf("cwd/.attach_pid%d", nsPid)),
		proc.Path(pid, fmt.Sprintf("root/tmp/.attach_pid%d", nsPid)),
	}
	if !checkSock(sockPath) {
		createdFile := ""
		for _, attachFile := range attachFiles {
			err = os.WriteFile(attachFile, []byte(""), 0660)
			if err != nil && !os.IsExist(err) {
				continue
			}
			createdFile = attachFile
			break
		}
		if createdFile != "" {
			defer os.Remove(createdFile)
		} else {
			return nil, err
		}
		if err = syscall.Kill(int(pid), syscall.SIGQUIT); err != nil {
			return nil, err
		}
		if err = waitForSock(sockPath); err != nil {
			return nil, err
		}
	}
	jvm := &JVM{}
	jvm.conn, err = net.DialTimeout("unix", sockPath, connectionTimeout)
	if err != nil {
		return nil, err
	}
	return jvm, nil
}

func (jvm *JVM) Close() error {
	return jvm.conn.Close()
}

func (jvm *JVM) DumpPerfmap() error {
	if err := jvm.conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	defer jvm.conn.SetDeadline(time.Time{})
	msg := strings.Join([]string{"1", "jcmd", "Compiler.perfmap", "", "", ""}, "\x00")
	if _, err := jvm.conn.Write([]byte(msg)); err != nil {
		return err
	}
	status := []byte{0}
	if _, err := jvm.conn.Read(status); err != nil {
		return err
	}
	if status[0] != '0' {
		return errors.New("status:" + string(status))
	}
	return nil
}

func waitForSock(p string) error {
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if checkSock(p) {
				return nil
			}
		}
	}
}

func checkSock(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeSocket != 0
}
