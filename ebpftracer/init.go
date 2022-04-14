package ebpftracer

import (
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
	"strings"
)

type file struct {
	pid uint32
	fd  uint32
}

type sock struct {
	pid uint32
	proc.Sock
}

func readFds(pids []uint32) (files []file, socks []sock) {
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

		fds, err := proc.ReadFds(pid)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			switch {
			case fd.SocketInode != "":
				if s, ok := sockets[fd.SocketInode]; ok {
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
