//go:build amd64

package ebpftracer

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"

	"github.com/containerd/cgroups"
	cgroupsV2 "github.com/containerd/cgroups/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func skipIfNotVM(t *testing.T) {
	if os.Getenv("VM") == "" {
		t.SkipNow()
	}
}

func TestProcessEvents(t *testing.T) {
	skipIfNotVM(t)
	src := `
		package main
		
		import (
			"bytes"
			"os"
			"strconv"
			"time"
		)
		
		func main() {
			mb, _ := strconv.Atoi(os.Args[1])
			sleep, _ := time.ParseDuration(os.Args[2])
			bytes.Repeat([]byte("x"), mb*1024*1024)
			time.Sleep(sleep)
		}
	`
	program := path.Join(t.TempDir(), "program")
	require.NoError(t, os.WriteFile(program+".go", []byte(src), 0644))
	require.NoError(t, exec.Command("go", "build", "-o", program, program+".go").Run())

	getEvent, stop := runTracer(t, false)
	defer stop()
	for {
		if e := getEvent(); e == nil {
			break
		}
	}

	p1 := exec.Command(program, "600", "10s")
	require.NoError(t, p1.Start())
	time.Sleep(time.Second)
	assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: uint32(p1.Process.Pid)}, *getEvent())

	// p1 should be killed by the OOM killer, because VM have only 1 GB of memory total
	p2 := exec.Command(program, "400", "1s")
	require.NoError(t, p2.Run())
	assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: uint32(p2.Process.Pid)}, *getEvent())

	require.Error(t, p1.Wait())
	assert.Equal(t, Event{Type: EventTypeProcessExit, Reason: EventReasonOOMKill, Pid: uint32(p1.Process.Pid)}, *getEvent())
	assert.Equal(t, Event{Type: EventTypeProcessExit, Pid: uint32(p2.Process.Pid)}, *getEvent())

	var limit int64 = 200 * 1024 * 1024
	// p3 should be killed by the OOM killer, because 300 MB > 200 MB cgroup limit
	p3 := exec.Command(program, "300", "3s")
	require.NoError(t, p3.Start())
	switch cgroups.Mode() {
	case cgroups.Legacy, cgroups.Hybrid:
		control, err := cgroups.New(cgroups.V1, cgroups.StaticPath("/program"), &specs.LinuxResources{
			Memory: &specs.LinuxMemory{Limit: &limit},
		})
		require.NoError(t, err)
		defer control.Delete()
		require.NoError(t, control.Add(cgroups.Process{Pid: p3.Process.Pid}))
	case cgroups.Unified:
		control, err := cgroupsV2.NewManager("/sys/fs/cgroup", "/program", &cgroupsV2.Resources{Memory: &cgroupsV2.Memory{Max: &limit}})
		require.NoError(t, err)
		defer control.Delete()
		require.NoError(t, control.AddProc(uint64(p3.Process.Pid)))
	}
	require.Error(t, p3.Wait())
	assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: uint32(p3.Process.Pid)}, *getEvent())
	assert.Equal(t, Event{Type: EventTypeProcessExit, Reason: EventReasonOOMKill, Pid: uint32(p3.Process.Pid)}, *getEvent())

	for {
		e := getEvent()
		if e == nil {
			break
		}
		t.Errorf("unexpected event %+v", e)
	}
}

func TestTcpEvents(t *testing.T) {
	skipIfNotVM(t)
	l, err := net.Listen("tcp", "127.0.0.1:8080")
	require.NoError(t, err)
	listenAddr := l.Addr().String()
	remoteAddr := "127.0.0.1:8080"
	c, err := net.DialTimeout("tcp", remoteAddr, 100*time.Millisecond)
	require.NoError(t, err)
	localAddr := c.LocalAddr().String()
	time.Sleep(100 * time.Millisecond)

	getEvent, stop := runTracer(t, false)
	defer stop()

	pid := uint32(os.Getpid())

	is := func(e *Event, typ EventType, sAddr string, dAddr string, pid uint32) bool {
		if e == nil {
			return false
		}
		sa := e.SrcAddr.String()
		if strings.HasSuffix(sAddr, ":") {
			sa = fmt.Sprintf("%s:", e.SrcAddr.IP())
		}
		da := e.DstAddr.String()
		return e.Type == typ && e.Pid == pid && sa == sAddr && da == dAddr
	}

	listenFound := false
	connectFound := false
	for {
		e := getEvent()
		if e == nil {
			break
		}
		if is(e, EventTypeListenOpen, listenAddr, "0.0.0.0:0", pid) {
			listenFound = true
		}
		if is(e, EventTypeConnectionOpen, localAddr, remoteAddr, pid) {
			connectFound = true
		}
	}
	if !listenFound {
		t.Errorf("expected %s on %s", EventTypeListenOpen, l.Addr())
	}
	if !connectFound {
		t.Errorf("expected %s to %s", EventTypeConnectionOpen, l.Addr())
	}

	nextIs := func(typ EventType, sAddr string, dAddr string, pid uint32) {
		e := getEvent()
		if !is(e, typ, sAddr, dAddr, pid) {
			expected := fmt.Sprintf("%-20s %6d: %s -> %s", typ, pid, sAddr, dAddr)
			actual := "nil"
			if e != nil {
				actual = fmt.Sprintf("%-20s %6d: %s -> %s", e.Type, e.Pid, e.SrcAddr, e.DstAddr)
			}
			assert.Equal(t, expected, actual)
		}
	}

	require.NoError(t, c.Close())
	nextIs(EventTypeConnectionClose, localAddr, listenAddr, 0)
	nextIs(EventTypeConnectionClose, listenAddr, localAddr, 0)

	require.NoError(t, l.Close())
	nextIs(EventTypeListenClose, listenAddr, "0.0.0.0:0", pid)

	c, err = net.DialTimeout("tcp", listenAddr, 100*time.Millisecond)
	require.Error(t, err)
	nextIs(EventTypeConnectionError, "127.0.0.1:", listenAddr, pid)

	l, err = net.Listen("tcp4", ":8080")
	require.NoError(t, err)
	listenAddr = l.Addr().String()
	nextIs(EventTypeListenOpen, listenAddr, "0.0.0.0:0", pid)

	c, err = net.DialTimeout("tcp", remoteAddr, 100*time.Millisecond)
	require.NoError(t, err)
	localAddr = c.LocalAddr().String()
	nextIs(EventTypeConnectionOpen, localAddr, remoteAddr, pid)

	require.NoError(t, exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "100%").Run())
	getEvent()
	getEvent()
	c.Write([]byte("hello"))
	nextIs(EventTypeTCPRetransmit, localAddr, remoteAddr, 0)
	require.NoError(t, exec.Command("tc", "qdisc", "del", "dev", "lo", "root", "netem").Run())
	getEvent()
	getEvent()
	func() {
		timer := time.NewTimer(time.Second)
		for {
			select {
			case <-timer.C:
				return
			default:
				e := getEvent()
				require.True(t, e == nil || e.Type == EventTypeTCPRetransmit)
			}
		}
	}()

	require.NoError(t, c.Close())
	nextIs(EventTypeConnectionClose, localAddr, remoteAddr, 0)
	nextIs(EventTypeConnectionClose, remoteAddr, localAddr, 0)

	require.NoError(t, l.Close())
	nextIs(EventTypeListenClose, listenAddr, "0.0.0.0:0", pid)

	for {
		e := getEvent()
		if e == nil {
			break
		}
		t.Errorf("unexpected event %+v", e)
	}
}

func TestFileEvents(t *testing.T) {
	skipIfNotVM(t)
	src := `
		package main
		
		import (
			"os"
			"strconv"
			"syscall"
			"unsafe"
			"time"
		)
		
		func main() {
			call, _ := strconv.Atoi(os.Args[1])
			path := os.Args[2]
			flags, _ := strconv.Atoi(os.Args[3])
			filename, _ := syscall.BytePtrFromString(path)
			var err syscall.Errno
			switch call {
			case syscall.SYS_OPEN:
				_, _, err = syscall.Syscall6(syscall.SYS_OPEN, uintptr(unsafe.Pointer(filename)), uintptr(flags), 0, 0, 0, 0)
			case syscall.SYS_OPENAT:
				AT_FDCWD := -100
				_, _, err = syscall.Syscall6(syscall.SYS_OPENAT, uintptr(AT_FDCWD), uintptr(unsafe.Pointer(filename)), uintptr(flags), 0, 0, 0)
			}
			time.Sleep(100 * time.Millisecond)
			os.Exit(int(err))
		}
	`
	require.NoError(t, os.Chdir(t.TempDir()))
	require.NoError(t, os.WriteFile("program.go", []byte(src), 0644))
	out, err := exec.Command("go", "build", "-o", "program", "program.go").CombinedOutput()
	require.Equal(t, "", string(out))
	require.NoError(t, err)

	getEvent, stop := runTracer(t, false)
	defer stop()
	for {
		if e := getEvent(); e == nil {
			break
		}
	}

	for _, call := range []int{syscall.SYS_OPEN, syscall.SYS_OPENAT} {
		run := func(file string, flag int) (uint32, error) {
			p := exec.Command("./program", strconv.Itoa(call), file, strconv.Itoa(flag))
			err := p.Run()
			return uint32(p.Process.Pid), err
		}

		pid, err := run("program.go", os.O_RDONLY)
		assert.NoError(t, err)
		assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: pid}, *getEvent())
		assert.Equal(t, Event{Type: EventTypeProcessExit, Pid: pid}, *getEvent())

		pid, err = run("program.go", os.O_WRONLY)
		assert.NoError(t, err)
		assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: pid}, *getEvent())
		assert.Equal(t, Event{Type: EventTypeFileOpen, Pid: pid, Fd: 3}, *getEvent())
		assert.Equal(t, Event{Type: EventTypeProcessExit, Pid: pid}, *getEvent())

		pid, err = run("program.go", os.O_RDWR)
		assert.NoError(t, err)
		assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: pid}, *getEvent())
		assert.Equal(t, Event{Type: EventTypeFileOpen, Pid: pid, Fd: 3}, *getEvent())
		assert.Equal(t, Event{Type: EventTypeProcessExit, Pid: pid}, *getEvent())

		// open error: text file busy
		pid, err = run("program", os.O_RDWR)
		assert.Error(t, err)
		assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: pid}, *getEvent())
		assert.Equal(t, Event{Type: EventTypeProcessExit, Pid: pid}, *getEvent())

		// ignoring /proc/*, /dev/*, /sys/*
		for _, f := range []string{"/proc/sys/fs/file-max", "/dev/null", "/sys/kernel/profiling"} {
			pid, err = run(f, os.O_RDWR)
			assert.NoError(t, err)
			assert.Equal(t, Event{Type: EventTypeProcessStart, Pid: pid}, *getEvent())
			assert.Equal(t, Event{Type: EventTypeProcessExit, Pid: pid}, *getEvent())
		}

		for {
			e := getEvent()
			if e == nil {
				break
			}
			t.Errorf("unexpected event %+v", e)
		}
	}
}

func runTracer(t *testing.T, verbose bool) (func() *Event, func()) {
	events := make(chan Event, 1000)
	done := make(chan bool, 1)

	var uname unix.Utsname
	assert.NoError(t, unix.Uname(&uname))
	assert.NoError(t, common.SetKernelVersion(string(bytes.Split(uname.Release[:], []byte{0})[0])))

	go func() {
		tt := NewTracer(0, 0, false)
		err := tt.Run(events)
		require.NoError(t, err)
		<-done
		tt.Close()
	}()

	stop := func() {
		done <- true
	}

	get := func() *Event {
		select {
		case e := <-events:
			if verbose {
				fmt.Printf("%+v\n", e)
			}
			return &e
		case <-time.NewTimer(time.Second).C:
			return nil
		}
	}

	return get, stop
}
