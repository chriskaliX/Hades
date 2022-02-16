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

// @Notes: cfs stands for Completely Fair Schedule
func sysvinitStart() error {
	cmd := exec.Command(agentFile)
	cmd.Dir = agentWorkDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	// viper 获取全部变量
	for k, v := range viper.AllSettings() {
		cmd.Env = append(cmd.Env, k+"="+v.(string))
	}
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	err := cmd.Start()
	if err != nil {
		return err
	}
	// set cgroup
	// 10% limited CPU usage
	quota := int64(10000)
	// 250M limit in Elkeid.
	// TODO: is this too high? I'm going to down this to 100M, under test, maybe size down the buffer is needed.
	memLimit := int64(104857600)
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
