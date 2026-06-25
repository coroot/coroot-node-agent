package node

type MemoryStat struct {
	TotalBytes     float64
	AvailableBytes float64
	FreeBytes      float64
	CachedBytes    float64
}

type CpuStat struct {
	TotalUsage   CpuUsage
	LogicalCores int
}

type CpuUsage struct {
	User    float64
	Nice    float64
	System  float64
	Idle    float64
	IoWait  float64
	Irq     float64
	SoftIrq float64
	Steal   float64
}
