package metrics

import (
	"agent/agent"
	"agent/proto"
	"agent/transport"
	"agent/transport/connection"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK/config"
	"github.com/coreos/go-systemd/daemon"
	"github.com/mitchellh/mapstructure"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"go.uber.org/zap"
)

var (
	kernelVersion   string
	arch            string
	platform        string
	platformFamily  string
	platformVersion string
	cpuNum          int
	cpuLogicalNum   int
	cpuMhz          string
	cpuName         string
	Memory          uint64

	bootTime uint64
)

func init() {
	kernelVersion, _ = host.KernelVersion()
	platform, platformFamily, platformVersion, _ = host.PlatformInformation()
	cpuNum, _ = cpu.Counts(false)
	cpuLogicalNum, _ = cpu.Counts(true)

	var mhz float64
	if info, err := cpu.Info(); err == nil && len(info) > 0 {
		for _, c := range info {
			mhz += c.Mhz
		}
		mhz /= float64(len(info))
		cpuName = info[0].ModelName
	}
	cpuMhz = strconv.FormatFloat(mhz/1000, 'f', 1, 64)

	if m, err := mem.VirtualMemory(); err == nil {
		Memory = m.Total
	}
	bootTime, _ = host.BootTime()

	addMetric(&AgentMetric{})
}

type AgentMetric struct {
	// constant fields
	KernelVersion   string `mapstructure:"kernel_version"`
	Arch            string `mapstructure:"arch"`
	Platform        string `mapstructure:"platform"`
	PlatformFamily  string `mapstructure:"platform_family"`
	PlatformVersion string `mapstructure:"platform_version"`
	CpuNum          string `mapstructure:"cpu_num"`
	CpuLogicalNum   string `mapstructure:"cpu_logical_num"`
	CpuMhz          string `mapstructure:"cpu_mhz"`
	CpuName         string `mapstructure:"cpu_name"`
	BootTime        string `mapstructure:"boot_at"`
	TotalMemory     string `mapstructure:"total_memory"`
	// Agent related inforamtion
	Pid         string `mapstructure:"pid"`
	Cpu         string `mapstructure:"cpu"`
	Rss         string `mapstructure:"rss"`
	ReadSpeed   string `mapstructure:"read_speed"`
	WriteSpeed  string `mapstructure:"write_speed"`
	TxSpeed     string `mapstructure:"tx_speed"`
	RxSpeed     string `mapstructure:"rx_speed"`
	FdCnt       string `mapstructure:"fd_cnt"`
	StartAt     string `mapstructure:"start_at"`
	TxTps       string `mapstructure:"tx_tps"`
	RxTps       string `mapstructure:"rx_tps"`
	Du          string `mapstructure:"du"`
	Grs         string `mapstructure:"grs"`
	Nproc       string `mapstructure:"nproc"`
	State       string `mapstructure:"state"`
	StateDetail string `mapstructure:"state_detail"`
	// Host related information
	SysCpu string `mapstructure:"sys_cpu"`
	SysMem string `mapstructure:"sys_mem"`
	Load1  string `mapstructure:"load_1"`
	Load5  string `mapstructure:"load_5"`
	Load15 string `mapstructure:"load_15"`
}

func (m *AgentMetric) Name() string {
	return "agent"
}

func (h *AgentMetric) Init() bool {
	return true
}

func (m *AgentMetric) Flush(now time.Time) {
	m.KernelVersion = kernelVersion
	m.Arch = arch
	m.Platform = platform
	m.PlatformFamily = platformFamily
	m.PlatformVersion = platformVersion
	m.CpuNum = strconv.Itoa(cpuNum)
	m.CpuLogicalNum = strconv.Itoa(cpuLogicalNum)
	m.CpuMhz = cpuMhz
	m.CpuName = cpuName
	m.TotalMemory = strconv.FormatUint(Memory, 10)
	m.BootTime = strconv.FormatUint(bootTime, 10)

	pid := os.Getpid()
	m.Pid = strconv.Itoa(pid)
	if cpu, rss, rs, ws, fdCnt, startAt, err := getProcResource(pid); err == nil {
		m.Cpu = strconv.FormatFloat(cpu, 'f', 8, 64)
		m.ReadSpeed = strconv.FormatFloat(rs, 'f', 8, 64)
		m.WriteSpeed = strconv.FormatFloat(ws, 'f', 8, 64)
		m.Rss = strconv.FormatUint(rss, 10)
		m.FdCnt = strconv.FormatInt(int64(fdCnt), 10)
		m.StartAt = strconv.FormatInt(startAt, 10)
	} else {
		zap.S().Error(err)
	}
	s := connection.DefaultStatsHandler.GetStats(now)
	m.RxSpeed = strconv.FormatFloat(s.RxSpeed, 'f', 8, 64)
	m.TxSpeed = strconv.FormatFloat(s.TxSpeed, 'f', 8, 64)
	txTPS, rxTPX := transport.DefaultTrans.GetState(now)
	m.TxTps = strconv.FormatFloat(txTPS, 'f', 8, 64)
	m.RxTps = strconv.FormatFloat(rxTPX, 'f', 8, 64)
	m.Du = strconv.FormatUint(getDirSize(agent.Workdir, "plugin"), 10)
	m.Grs = strconv.Itoa(runtime.NumGoroutine())
	m.Nproc = strconv.Itoa(runtime.NumCPU())
	m.State, m.StateDetail = agent.State()

	if cpuPercents, err := cpu.Percent(0, false); err == nil {
		m.SysCpu = strconv.FormatFloat(cpuPercents[0], 'f', 8, 64)
	}
	if mem, err := mem.VirtualMemory(); err == nil {
		m.SysMem = strconv.FormatFloat(mem.UsedPercent, 'f', 8, 64)
	}

	if runtime.GOOS == "linux" {
		if avg, err := load.Avg(); err == nil {
			m.Load1 = strconv.FormatFloat(avg.Load1, 'f', 2, 64)
			m.Load5 = strconv.FormatFloat(avg.Load5, 'f', 2, 64)
			m.Load15 = strconv.FormatFloat(avg.Load15, 'f', 2, 64)
		}
		daemon.SdNotify(false, "WATCHDOG=1")
	}

	fields := make(map[string]string, 28)
	if err := mapstructure.Decode(m, fields); err == nil {
		rec := &proto.Record{
			DataType:  config.DTPluginStatus,
			Timestamp: now.Unix(),
			Data: &proto.Payload{
				Fields: fields,
			},
		}
		transport.DefaultTrans.Transmission(rec, false)
	}
}
