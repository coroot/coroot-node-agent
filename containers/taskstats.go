package containers

import (
	"fmt"
	"github.com/mdlayher/taskstats"
	"sync"
)

var (
	taskstatsClient *taskstats.Client
	taskstatsLock   sync.Mutex
)

func TaskstatsInit() error {
	c, err := taskstats.New()
	if err != nil {
		return err
	}
	taskstatsClient = c
	return nil
}

func TaskstatsTGID(pid uint32) (*taskstats.Stats, error) {
	if taskstatsClient == nil {
		return nil, fmt.Errorf("taskstats client not initialized")
	}
	taskstatsLock.Lock()
	defer taskstatsLock.Unlock()
	s, err := taskstatsClient.TGID(int(pid))
	if err != nil {
		return nil, err
	}
	return s, nil
}

func TaskstatsPID(pid uint32) (*taskstats.Stats, error) {
	if taskstatsClient == nil {
		return nil, fmt.Errorf("taskstats client not initialized")
	}
	taskstatsLock.Lock()
	defer taskstatsLock.Unlock()
	s, err := taskstatsClient.PID(int(pid))
	if err != nil {
		return nil, err
	}
	return s, nil
}
