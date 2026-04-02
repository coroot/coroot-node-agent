package jvm

import (
	"fmt"
	"io"
	"time"

	"github.com/google/pprof/profile"
	"github.com/grafana/jfr-parser/parser"
	"github.com/grafana/jfr-parser/parser/types"
)

const (
	ProfileTypeAllocObjects    = "java:heap_alloc_objects:count"
	ProfileTypeAllocSpace      = "java:heap_alloc_space:bytes"
	ProfileTypeCPU             = "java:cpu:nanoseconds"
	ProfileTypeLockContentions = "java:lock_contentions:count"
	ProfileTypeLockDelay       = "java:lock_delay:nanoseconds"

	cpuSamplePeriodNs = 10_000_000 // 10ms — matches itimer default
)

type JavaProfile struct {
	Type string
	Prof *profile.Profile
}

type sampleAcc struct {
	locs []*profile.Location
	vals []int64
}

func ParseProfiles(jfrData []byte, duration time.Duration) ([]JavaProfile, error) {
	p := parser.NewParser(jfrData, parser.Options{SymbolProcessor: parser.ProcessSymbols})

	allocSamples := map[string]*sampleAcc{}
	cpuSamples := map[string]*sampleAcc{}
	lockSamples := map[string]*sampleAcc{}

	funcMap := map[string]*profile.Function{}
	locMap := map[string]*profile.Location{}
	var funcID, locID uint64

	type resolvedFrame struct {
		className  string
		methodName string
		fullName   string
		line       uint32
	}

	resolveStack := func(stRef types.StackTraceRef) ([]resolvedFrame, string) {
		st := p.GetStacktrace(stRef)
		if st == nil {
			return nil, ""
		}
		frames := make([]resolvedFrame, 0, len(st.Frames))
		key := ""
		for _, f := range st.Frames {
			m := p.GetMethod(f.Method)
			if m == nil {
				continue
			}
			cls := p.GetClass(m.Type)
			clsName := ""
			if cls != nil {
				clsName = p.GetSymbolString(cls.Name)
			}
			methodName := p.GetSymbolString(m.Name)
			fullName := clsName + "." + methodName
			frames = append(frames, resolvedFrame{clsName, methodName, fullName, f.LineNumber})
			key += fullName + ";"
		}
		return frames, key
	}

	addToAcc := func(acc map[string]*sampleAcc, stRef types.StackTraceRef, nVals int, valsFn func([]int64) []int64) {
		frames, key := resolveStack(stRef)
		if key == "" {
			return
		}
		s := acc[key]
		if s == nil {
			locs := make([]*profile.Location, len(frames))
			for i, f := range frames {
				locKey := fmt.Sprintf("%s.%s:%d", f.className, f.methodName, f.line)
				loc := locMap[locKey]
				if loc == nil {
					fn := funcMap[f.fullName]
					if fn == nil {
						funcID++
						fn = &profile.Function{ID: funcID, Name: f.fullName, Filename: f.className}
						funcMap[f.fullName] = fn
					}
					locID++
					loc = &profile.Location{
						ID:   locID,
						Line: []profile.Line{{Function: fn, Line: int64(f.line)}},
					}
					locMap[locKey] = loc
				}
				locs[i] = loc
			}
			s = &sampleAcc{locs: locs, vals: make([]int64, nVals)}
			acc[key] = s
		}
		s.vals = valsFn(s.vals)
	}

	for {
		typ, err := p.ParseEvent()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch typ {
		case p.TypeMap.T_EXECUTION_SAMPLE:
			addToAcc(cpuSamples, p.ExecutionSample.StackTrace, 1, func(v []int64) []int64 {
				v[0] += cpuSamplePeriodNs
				return v
			})
		case p.TypeMap.T_ALLOC_SAMPLE:
			addToAcc(allocSamples, p.ObjectAllocationSample.StackTrace, 2, func(v []int64) []int64 {
				v[0]++
				v[1] += int64(p.ObjectAllocationSample.Weight)
				return v
			})
		case p.TypeMap.T_ALLOC_IN_NEW_TLAB:
			addToAcc(allocSamples, p.ObjectAllocationInNewTLAB.StackTrace, 2, func(v []int64) []int64 {
				v[0]++
				v[1] += int64(p.ObjectAllocationInNewTLAB.TlabSize)
				return v
			})
		case p.TypeMap.T_ALLOC_OUTSIDE_TLAB:
			addToAcc(allocSamples, p.ObjectAllocationOutsideTLAB.StackTrace, 2, func(v []int64) []int64 {
				v[0]++
				v[1] += int64(p.ObjectAllocationOutsideTLAB.AllocationSize)
				return v
			})
		case p.TypeMap.T_MONITOR_ENTER:
			addToAcc(lockSamples, p.JavaMonitorEnter.StackTrace, 2, func(v []int64) []int64 {
				v[0]++
				v[1] += int64(p.JavaMonitorEnter.Duration)
				return v
			})
		}
	}

	var result []JavaProfile

	if len(cpuSamples) > 0 {
		result = append(result,
			buildProfile(ProfileTypeCPU, cpuSamples, 0, duration,
				[]*profile.ValueType{{Type: ProfileTypeCPU, Unit: "nanoseconds"}},
				&profile.ValueType{Type: "cpu", Unit: "nanoseconds"}),
		)
	}

	if len(allocSamples) > 0 {
		result = append(result,
			buildProfile(ProfileTypeAllocObjects, allocSamples, 0, duration,
				[]*profile.ValueType{{Type: ProfileTypeAllocObjects, Unit: "count"}},
				&profile.ValueType{Type: "space", Unit: "bytes"}),
			buildProfile(ProfileTypeAllocSpace, allocSamples, 1, duration,
				[]*profile.ValueType{{Type: ProfileTypeAllocSpace, Unit: "bytes"}},
				&profile.ValueType{Type: "space", Unit: "bytes"}),
		)
	}

	if len(lockSamples) > 0 {
		result = append(result,
			buildProfile(ProfileTypeLockContentions, lockSamples, 0, duration,
				[]*profile.ValueType{{Type: ProfileTypeLockContentions, Unit: "count"}},
				&profile.ValueType{Type: "lock", Unit: "count"}),
			buildProfile(ProfileTypeLockDelay, lockSamples, 1, duration,
				[]*profile.ValueType{{Type: ProfileTypeLockDelay, Unit: "nanoseconds"}},
				&profile.ValueType{Type: "lock", Unit: "nanoseconds"}),
		)
	}

	return result, nil
}

func buildProfile(typeName string, samples map[string]*sampleAcc, valIdx int, duration time.Duration, sampleTypes []*profile.ValueType, periodType *profile.ValueType) JavaProfile {
	prof := &profile.Profile{
		SampleType:    sampleTypes,
		TimeNanos:     time.Now().UnixNano(),
		DurationNanos: duration.Nanoseconds(),
		PeriodType:    periodType,
	}

	seenFuncs := map[uint64]bool{}
	seenLocs := map[uint64]bool{}

	for _, s := range samples {
		prof.Sample = append(prof.Sample, &profile.Sample{
			Location: s.locs,
			Value:    []int64{s.vals[valIdx]},
		})
		for _, loc := range s.locs {
			if !seenLocs[loc.ID] {
				seenLocs[loc.ID] = true
				prof.Location = append(prof.Location, loc)
				for _, line := range loc.Line {
					if !seenFuncs[line.Function.ID] {
						seenFuncs[line.Function.ID] = true
						prof.Function = append(prof.Function, line.Function)
					}
				}
			}
		}
	}

	return JavaProfile{Type: typeName, Prof: prof}
}
