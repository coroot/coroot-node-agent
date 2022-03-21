package cgroup

import (
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

func TestCgroup_IOStat(t *testing.T) {
	cgRoot = "fixtures/cgroup"

	cg, _ := NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	stat, err := cg.IOStat()
	assert.Nil(t, err)
	assert.Equal(t,
		map[string]IOStat{
			"8:0":  {ReadOps: 0, WriteOps: 281, ReadBytes: 0, WrittenBytes: 4603904},
			"8:16": {ReadOps: 0, WriteOps: 39, ReadBytes: 0, WrittenBytes: 655360},
			"8:32": {ReadOps: 23043666, WriteOps: 28906992, ReadBytes: 998632854016, WrittenBytes: 884175858688},
			"8:48": {ReadOps: 20689345, WriteOps: 27906791, ReadBytes: 875529547776, WrittenBytes: 753046432768},
			"9:1":  {ReadOps: 633949, WriteOps: 4, ReadBytes: 10238894080, WrittenBytes: 49152},
		},
		stat)

	cg, _ = NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	stat, err = cg.IOStat()
	assert.Nil(t, err)
	assert.Equal(t,
		map[string]IOStat{
			"252:0": {ReadOps: 22, WriteOps: 57111, ReadBytes: 11, WrittenBytes: 630538240},
			"253:0": {ReadOps: 44, WriteOps: 57056, ReadBytes: 33, WrittenBytes: 630538241},
		},
		stat)

}
