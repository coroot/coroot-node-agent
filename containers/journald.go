package containers

import (
	"fmt"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
)

var (
	journaldReader *logs.JournaldReader
)

func JournaldInit() error {
	r, err := logs.NewJournaldReader(
		proc.HostPath("/run/log/journal"),
		proc.HostPath("/var/log/journal"),
	)
	if err != nil {
		return err
	}
	journaldReader = r
	return nil
}

func JournaldSubscribe(cg *cgroup.Cgroup, ch chan<- logparser.LogEntry) error {
	if journaldReader == nil {
		return fmt.Errorf("journald reader not initialized")
	}
	err := journaldReader.Subscribe(cg.Id, ch)
	if err != nil {
		return err
	}
	return nil
}

func JournaldUnsubscribe(cg *cgroup.Cgroup) {
	if journaldReader == nil {
		return
	}
	journaldReader.Unsubscribe(cg.Id)
}
