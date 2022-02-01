package heartbeat

import (
	"agent/agent"
	"agent/host"
	"agent/internal"
	"agent/plugin"
	"agent/proto"
	"agent/resource"
	"context"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"go.uber.org/zap"
)

func getAgentStat(now time.Time) {
	rec := &proto.Record{
		DataType:  internal.AgentStatus,
		Timestamp: now.Unix(),
		Data: &proto.Payload{
			Fields: map[string]string{},
		},
	}
	rec.Data.Fields["kernel_version"] = host.KernelVersion
	rec.Data.Fields["arch"] = host.Arch
	rec.Data.Fields["platform"] = host.Platform
	rec.Data.Fields["platform_family"] = host.PlatformFamily
	rec.Data.Fields["platform_version"] = host.PlatformVersion
	// add cpu information
	rec.Data.Fields["cpu_num"] = host.CpuNum
	rec.Data.Fields["cpu_mhz"] = host.CpuMhz

	// idc/region/net_mode/rx(tx)_speed not added

	cpuPercent, rss, readSpeed, writeSpeed, fds, startAt, err := resource.GetProcResouce(os.Getpid())
	if err != nil {
		// TODO: log here
	} else {
		rec.Data.Fields["cpu"] = strconv.FormatFloat(cpuPercent, 'f', 8, 64)
		rec.Data.Fields["rss"] = strconv.FormatUint(rss, 10)
		rec.Data.Fields["read_speed"] = strconv.FormatFloat(readSpeed, 'f', 8, 64)
		rec.Data.Fields["write_speed"] = strconv.FormatFloat(writeSpeed, 'f', 8, 64)
		rec.Data.Fields["pid"] = strconv.Itoa(os.Getpid())
		rec.Data.Fields["fd_cnt"] = strconv.FormatInt(int64(fds), 10)
		rec.Data.Fields["started_at"] = strconv.FormatInt(startAt, 10)
	}

	// transfer service not addes

	// change load to gopsutil
	rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(agent.WorkingDirectory, "plugin"), 10)
	rec.Data.Fields["grs"] = strconv.Itoa(runtime.NumGoroutine())
	rec.Data.Fields["nproc"] = strconv.Itoa(runtime.NumCPU())
	if runtime.GOOS == "linux" {
		if avg, err := load.Avg(); err == nil {
			rec.Data.Fields["load_1"] = strconv.FormatFloat(avg.Load1, 'f', 2, 64)
			rec.Data.Fields["load_5"] = strconv.FormatFloat(avg.Load5, 'f', 2, 64)
			rec.Data.Fields["load_15"] = strconv.FormatFloat(avg.Load15, 'f', 2, 64)
		}
		if misc, err := load.Misc(); err == nil {
			rec.Data.Fields["running_procs"] = strconv.Itoa(misc.ProcsRunning)
			rec.Data.Fields["total_procs"] = strconv.Itoa(misc.ProcsTotal)
		}
	}
	rec.Data.Fields["boot_at"] = strconv.FormatUint(resource.GetBootTime(), 10)
	// TODO: dig out if its wrong
	cpuPercents, err := cpu.Percent(0, false)
	if err != nil {
		rec.Data.Fields["sys_cpu"] = strconv.FormatFloat(cpuPercents[0], 'f', 8, 64)
	}
	mem, err := mem.VirtualMemory()
	if err != nil {
		rec.Data.Fields["sys_mem"] = strconv.FormatFloat(mem.UsedPercent, 'f', 8, 64)
	}
	
	// report here
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	plgManager := plugin.NewManager()
	defer wg.Done()
	zap.S().Info("health daemon startup")
	getAgentStat(time.Now())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			{
				host.RefreshHost()
				getAgentStat(t)
				plgManager.GetPlgStat(t)
			}
		}
	}
}
