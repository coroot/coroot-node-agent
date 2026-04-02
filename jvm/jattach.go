package jvm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/coroot/coroot-node-agent/proc"
)

const (
	connectionTimeout = 5 * time.Second
	requestTimeout    = 10 * time.Second
)

func dial(pid uint32) (net.Conn, error) {
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
	return net.DialTimeout("unix", sockPath, connectionTimeout)
}

// Each call opens a new connection (HotSpot closes the socket after each command).
func sendCommand(pid uint32, msg string) (byte, string, error) {
	conn, err := dial(pid)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(requestTimeout))

	if _, err := conn.Write([]byte(msg)); err != nil {
		return 0, "", err
	}
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		return 0, "", err
	}
	var buf bytes.Buffer
	io.Copy(&buf, conn)
	return status[0], strings.TrimSpace(buf.String()), nil
}

func LoadAgent(pid uint32, agentPath, args string) error {
	msg := strings.Join([]string{"1", "load", "instrument", "false", agentPath + "=" + args}, "\x00") + "\x00"
	status, resp, err := sendCommand(pid, msg)
	if err != nil {
		return err
	}
	if status != '0' {
		return fmt.Errorf("load agent failed: status=%c response=%s", status, resp)
	}
	return nil
}

func LoadNativeAgent(pid uint32, agentPath, args string) error {
	msg := strings.Join([]string{"1", "load", agentPath, "true", args}, "\x00") + "\x00"
	status, resp, err := sendCommand(pid, msg)
	if err != nil {
		return err
	}
	if status != '0' {
		return fmt.Errorf("load native agent failed: status=%c response=%s", status, resp)
	}
	return nil
}

func DumpPerfmap(pid uint32) error {
	msg := strings.Join([]string{"1", "jcmd", "Compiler.perfmap", "", "", ""}, "\x00")
	status, resp, err := sendCommand(pid, msg)
	if err != nil {
		return fmt.Errorf("failed to dump perfmap of JVM %d: %w", pid, err)
	}
	if status != '0' {
		return fmt.Errorf("failed to dump perfmap of JVM %d: status=%c response=%s", pid, status, resp)
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
