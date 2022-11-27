/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/containerd/cgroups"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func V1() (systems []cgroups.Subsystem, err error) {
	systems, err = cgroups.V1()
	if err != nil {
		return
	}
	if _, err := os.Stat(filepath.Join(agentWorkDir, "cgroup", "cpu", "tasks")); err == nil {
		systems = append(systems, cgroups.NewCpu(filepath.Join(agentWorkDir, "cgroup")))
	}
	if _, err := os.Stat(filepath.Join(agentWorkDir, "cgroup", "memory", "tasks")); err == nil {
		systems = append(systems, cgroups.NewMemory(filepath.Join(agentWorkDir, "cgroup")))
	}
	return
}

func sysvinitStart() error {
	cmd := exec.Command(agentFile)
	cmd.Dir = agentWorkDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	for k, v := range viper.AllSettings() {
		cmd.Env = append(cmd.Env, k+"="+v.(string))
	}
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	err := cmd.Start()
	if err != nil {
		return err
	}
	// Cpu 10%, Mem 300M
	quota := int64(10000)
	memLimit := int64(1024 * 1024 * 300)
	cg, err := cgroups.New(V1,
		cgroups.StaticPath(cgroupPath),
		&specs.LinuxResources{
			CPU: &specs.LinuxCPU{
				Quota: &quota,
			},
			Memory: &specs.LinuxMemory{
				Limit: &memLimit,
			},
		})
	if err == nil {
		return cg.AddProc(uint64(cmd.Process.Pid))
	}
	return err
}

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "start", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
			// sysvinit + crontab
		} else if viper.GetString("service_type") == "sysvinit" {
			err := sysvinitStart()
			cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			cobra.CheckErr(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
