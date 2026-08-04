package profiling

import (
	"encoding/binary"

	pprofProfile "github.com/google/pprof/profile"
)

func pruneProfile(p *pprofProfile.Profile, minFraction float64) *pprofProfile.Profile {
	if p == nil || minFraction <= 0 || len(p.Sample) == 0 {
		return p
	}
	dims := len(p.SampleType)
	if dims == 0 {
		return p
	}

	thresholds := make([]int64, dims)
	for _, s := range p.Sample {
		for i := 0; i < dims && i < len(s.Value); i++ {
			if s.Value[i] > 0 {
				thresholds[i] += s.Value[i]
			}
		}
	}
	var prunable bool
	for i := range thresholds {
		thresholds[i] = int64(float64(thresholds[i]) * minFraction)
		if thresholds[i] > 0 {
			prunable = true
		}
	}
	if !prunable {
		return p
	}

	type node struct {
		children map[uint64]*node
		totals   []int64
	}
	root := &node{children: map[uint64]*node{}}
	for _, s := range p.Sample {
		n := root
		for i := len(s.Location) - 1; i >= 0; i-- { // pprof stacks are leaf-first
			c := n.children[s.Location[i].ID]
			if c == nil {
				c = &node{children: map[uint64]*node{}, totals: make([]int64, dims)}
				n.children[s.Location[i].ID] = c
			}
			for j := 0; j < dims && j < len(s.Value); j++ {
				c.totals[j] += s.Value[j]
			}
			n = c
		}
	}
	significant := func(n *node) bool {
		for i, v := range n.totals {
			if thresholds[i] > 0 && v >= thresholds[i] {
				return true
			}
		}
		return false
	}

	samples := make([]*pprofProfile.Sample, 0, len(p.Sample))
	merged := map[string]*pprofProfile.Sample{}
	var key []byte
	for _, s := range p.Sample {
		n := root
		keep := 0
		for i := len(s.Location) - 1; i >= 0; i-- {
			c := n.children[s.Location[i].ID]
			if !significant(c) {
				break
			}
			keep++
			n = c
		}
		if keep < len(s.Location) {
			s.Location = s.Location[len(s.Location)-keep:]
		}
		if len(s.Label) > 0 || len(s.NumLabel) > 0 {
			samples = append(samples, s)
			continue
		}
		key = key[:0]
		for _, l := range s.Location {
			key = binary.AppendUvarint(key, l.ID)
		}
		if prev := merged[string(key)]; prev != nil {
			for i := 0; i < len(prev.Value) && i < len(s.Value); i++ {
				prev.Value[i] += s.Value[i]
			}
			continue
		}
		merged[string(key)] = s
		samples = append(samples, s)
	}
	p.Sample = samples

	usedLocs := make(map[uint64]bool, len(p.Location))
	usedFuncs := map[uint64]bool{}
	for _, s := range p.Sample {
		for _, l := range s.Location {
			if usedLocs[l.ID] {
				continue
			}
			usedLocs[l.ID] = true
			for _, ln := range l.Line {
				if ln.Function != nil {
					usedFuncs[ln.Function.ID] = true
				}
			}
		}
	}
	if len(usedLocs) == len(p.Location) {
		return p
	}
	locations := make([]*pprofProfile.Location, 0, len(usedLocs))
	for _, l := range p.Location {
		if usedLocs[l.ID] {
			locations = append(locations, l)
		}
	}
	p.Location = locations
	functions := make([]*pprofProfile.Function, 0, len(usedFuncs))
	for _, f := range p.Function {
		if usedFuncs[f.ID] {
			functions = append(functions, f)
		}
	}
	p.Function = functions
	return p
}
