/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	"github.com/nightlyone/lockfile"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// 这样 ProcTree 是否有问题
func getProcTreeWithProc(pid int) (res []int, err error) {
	if pid == 0 || pid == 1 {
		return nil, errors.New("proc tree includes init")
	}
	var procs []*process.Process
	procs, err = process.Processes()
	if err == nil {
		procMap := map[int32]struct{}{int32(pid): {}}
		for _, proc := range procs {
			if proc.Pid == 0 || proc.Pid == 1 {
				return nil, errors.New("proc tree includes init")
			}
			ppid, err := proc.Ppid()
			if err != nil {
				continue
			}
			if _, ok := procMap[ppid]; ok {
				procMap[proc.Pid] = struct{}{}
				continue
			}
			if exe, err := proc.Exe(); err == nil && strings.HasPrefix(exe, agentWorkDir) && os.Getpid() != int(proc.Pid) {
				procMap[proc.Pid] = struct{}{}
				continue
			}
		}
		for k := range procMap {
			res = append(res, int(k))
		}
	}
	return
}

func getProcTreeWithCgroup(pid int) (res []int, err error) {
	var cg cgroups.Cgroup
	cg, err = cgroups.Load(V1, cgroups.StaticPath(cgroupPath))
	if err != nil {
		return
	}
	var procs []cgroups.Process
	procs, err = cg.Processes(cgroups.Cpu, false)
	if err == nil {
		for _, p := range procs {
			if p.Pid == 0 || p.Pid == 1 {
				return nil, errors.New("proc tree includes init")
			}
			res = append(res, int(p.Pid))
		}
	}
	if len(res) == 0 {
		err = errors.New("could not find procs")
	}
	return
}

func sysvinitStop() error {
	os.RemoveAll(crontabFile)
	file, _ := lockfile.New(agentPidFile)
	p, err := file.GetOwner()
	if err == nil {
		var getProcTree func(int) (res []int, err error)
		var pids []int
		// 根据 cgroup 下获取 PID
		pids, err := getProcTreeWithCgroup(p.Pid)
		// cgroup mode
		if err == nil {
			getProcTree = getProcTreeWithCgroup
		// 根据进程树获取
		} else {
			// procfs mode
			pids, _ = getProcTreeWithProc(p.Pid)
			getProcTree = getProcTreeWithProc
		}
		// kill 掉所有的
		for _, pid := range pids {
			syscall.Kill(pid, syscall.SIGTERM)
		}
		ticker := time.NewTicker(time.Millisecond * time.Duration(100))
		defer ticker.Stop()
		timeout := time.NewTimer(time.Second * time.Duration(30))
		defer timeout.Stop()
	OUT:
		for {
			select {
			case <-ticker.C:
				pids, _ := getProcTree(p.Pid)
				if len(pids) == 0 {
					break OUT
				}
			case <-timeout.C:
				pids, _ := getProcTree(p.Pid)
				for _, pid := range pids {
					syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	}
	return nil
}

// stopCmd represents the stop command
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "stop", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
			os.RemoveAll(crontabFile)
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			sysvinitStop()
		}
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
