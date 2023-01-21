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

// sysvinit start with cgroup well setted
// THIS IS UNDER FULL TEST
func sysvinitStart() error {
	// run the command
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
	// if cgroup do not work as expected, quit the agent
	// should cgroup2 being covered? MAY EVENT NOT IN SYSVINIT
	// cgroup here
	// cgroup v2 need kernel version over 5.8, PRETTY SURE no sysvinit available

	// resource limitation
	quota := int64(10000)
	// period := uint64(100000)
	memory := int64(1024 * 1024 * 250)
	// pre check the cgroup
	cg, err := cgroups.Load(V1, cgroups.StaticPath(cgroupPath))
	if err == nil {
		return cg.AddProc(uint64(cmd.Process.Pid))
	}
	// not exist, new a cgroup
	// Cpu 10%, Mem 250M
	cg, err = cgroups.New(V1,
		cgroups.StaticPath(cgroupPath),
		&specs.LinuxResources{
			CPU: &specs.LinuxCPU{
				Quota: &quota,
			},
			Memory: &specs.LinuxMemory{
				Limit: &memory,
			},
		})
	if err == nil {
		return cg.AddProc(uint64(cmd.Process.Pid))
	}
	// WARNING: MOUNTING NOT READY, need to mount
	// cat /proc/self/mountinfo|grep -q 'cgroup .* rw,.*\bmemory\b'
	// if [ $? -ne 0 ];then
	//     info "memory cgroup is umounted, trying mounting"
	//     expect "mkdir -p ${root_dir}/cgroup/memory"
	//     expect "mount -t cgroup -o memory cgroup ${root_dir}/cgroup/memory"
	// fi
	// cat /proc/self/mountinfo|grep -q 'cgroup .* rw,.*\bcpu\b'
	// if [ $? -ne 0 ];then
	//     info "cpu cgroup is umounted, trying mounting"
	//     expect "mkdir -p ${root_dir}/cgroup/cpu"
	//     expect "mount -t cgroup -o cpu cgroup ${root_dir}/cgroup/cpu"
	// fi
	return err
}

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start the agent",
	Run: func(cmd *cobra.Command, args []string) {
		var service_type = viper.GetString("service_type")
		switch service_type {
		case "systemd":
			cmd := exec.Command("systemctl", "start", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		case "sysvinit":
			cobra.CheckErr(sysvinitStart())
			cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
