package ebpftracer

import (
	"strings"

	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

type file struct {
	pid uint32
	fd  uint64
}

type sock struct {
	pid uint32
	fd  uint64
	proc.Sock
}

func readFds(pids []uint32) (files []file, socks []sock) {
	nss := map[string]map[string]sock{}
	for _, pid := range pids {
		ns, err := proc.GetNetNs(pid)
		if err != nil {
			klog.Warningf("failed to get net ns for %d: %s", pid, err)
			continue
		}
		nsId := ns.UniqueId()
		sockets, ok := nss[nsId]
		_ = ns.Close()
		if !ok {
			if ss, err := proc.GetSockets(pid); err != nil {
				klog.Warningf("failed to get sockets for %d: %s", pid, err)
			} else {
				sockets = map[string]sock{}
				nss[nsId] = sockets
				for _, s := range ss {
					sockets[s.Inode] = sock{Sock: s}
				}
			}
		}

		fds, err := proc.ReadFds(pid)
		if err != nil {
			klog.Warningf("failed to read fds for %d: %s", pid, err)
			continue
		}
		for _, fd := range fds {
			switch {
			case fd.SocketInode != "":
				if s, ok := sockets[fd.SocketInode]; ok {
					s.fd = fd.Fd
					s.pid = pid
					socks = append(socks, s)
				}
			case strings.HasPrefix(fd.Dest, "/"):
				files = append(files, file{pid: pid, fd: fd.Fd})
			}
		}
	}
	return
}
