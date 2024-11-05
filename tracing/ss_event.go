// Uploads server-side events (response related events)

package tracing

import (
	"context"
	"k8s.io/klog/v2"
	"sync"
	"time"

	"github.com/ClickHouse/ch-go"
	chproto "github.com/ClickHouse/ch-go/proto"
)

const (
	SSEBatchLimit   = 50 // l7_event_ss processing batch size
	SSEBatchTimeout = 5 * time.Second
)

type SSEventBatcher struct {
	limit  int
	client *ch.Client

	lock sync.Mutex
	done chan struct{}

	Timestamp   *chproto.ColDateTime64
	Duration    *chproto.ColUInt64
	TgidRead    *chproto.ColUInt64
	TgidWrite   *chproto.ColUInt64
	StatementID *chproto.ColUInt32
}

func NewSSEventBatcher(limit int, timeout time.Duration, client *ch.Client) *SSEventBatcher {
	b := &SSEventBatcher{
		limit:  limit,
		client: client,

		done: make(chan struct{}),

		Timestamp:   new(chproto.ColDateTime64).WithPrecision(chproto.PrecisionNano),
		Duration:    new(chproto.ColUInt64),
		TgidRead:    new(chproto.ColUInt64),
		TgidWrite:   new(chproto.ColUInt64),
		StatementID: new(chproto.ColUInt32),
	}

	go func() {
		ticker := time.NewTicker(timeout)
		defer ticker.Stop()
		for {
			select {
			case <-b.done:
				return
			case <-ticker.C:
				b.lock.Lock()
				b.save()
				b.lock.Unlock()
			}
		}
	}()

	return b
}

func (b *SSEventBatcher) Append(timestamp uint64, duration time.Duration, TgidReqSs, TgidRespSs uint64) {
	b.Timestamp.Append(time.Unix(0, int64(timestamp)))
	b.Duration.Append(uint64(duration))
	b.TgidRead.Append(TgidReqSs)
	b.TgidWrite.Append(TgidRespSs)
	b.StatementID.Append(0) // todo support something like x-request-id

	if b.Timestamp.Rows() < b.limit {
		return
	}
	b.save()
}

func (b *SSEventBatcher) Close() {
	b.done <- struct{}{}
	b.lock.Lock()
	b.save()
	b.lock.Unlock()
}

func (b *SSEventBatcher) save() {
	if b.Timestamp.Rows() == 0 {
		return
	}

	input := chproto.Input{
		{Name: "Timestamp", Data: b.Timestamp},
		{Name: "Duration", Data: b.Duration},
		{Name: "StatementId", Data: b.StatementID},
		{Name: "TgidRead", Data: b.TgidRead},
		{Name: "TgidWrite", Data: b.TgidWrite},
	}
	query := ch.Query{Body: input.Into("l7_events_ss"), Input: input}
	err := b.client.Do(context.Background(), query)
	if err != nil {
		klog.Errorln(err)
	}
	for _, i := range input {
		i.Data.(chproto.Resettable).Reset()
	}
}
