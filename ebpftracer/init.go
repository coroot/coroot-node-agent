package ebpftracer

import (
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
	"os"
	"path"
	"strconv"
	"strings"
)

type fd struct {
	pid uint32
	fd  uint32
}

type sock struct {
	pid uint32
	proc.Sock
}

func readFds(pids []uint32) (fds []fd, socks []sock) {
	nss := map[string]map[string]sock{}
	for _, pid := range pids {
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			continue
		}
		nsId := ns.UniqueId()
		sockets, ok := nss[nsId]
		_ = ns.Close()
		if !ok {
			sockets = map[string]sock{}
			nss[nsId] = sockets
			if ss, err := proc.GetSockets(pid); err != nil {
				klog.Warningln(err)
			} else {
				for _, s := range ss {
					sockets[s.Inode] = sock{Sock: s}
				}
			}
		}

		fdDir := proc.Path(pid, "fd")
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			dest, err := os.Readlink(path.Join(fdDir, entry.Name()))
			if err != nil {
				continue
			}
			switch {
			case strings.HasPrefix(dest, "socket:[") && strings.HasSuffix(dest, "]"):
				inode := dest[len("socket:[") : len(dest)-1]
				if s, ok := sockets[inode]; ok {
					s.pid = pid
					socks = append(socks, s)
				}
			default:
				i, err := strconv.Atoi(entry.Name())
				if err == nil {
					fds = append(fds, fd{pid: pid, fd: uint32(i)})
				}
			}
		}
	}
	return
}
