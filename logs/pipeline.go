package logs

import "github.com/coroot/logparser"

type Pipeline struct {
	parser *logparser.Parser
	stop   func()
}

func NewPipeline(parser *logparser.Parser, stop func()) *Pipeline {
	return &Pipeline{parser: parser, stop: stop}
}

func (p *Pipeline) Counters() []logparser.LogCounter {
	return p.parser.GetCounters()
}

func (p *Pipeline) Stop() {
	if p.stop != nil {
		p.stop()
	}
	p.parser.Stop()
}
