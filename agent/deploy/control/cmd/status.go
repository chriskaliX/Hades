/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/nightlyone/lockfile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "show agent status",
	Run: func(cmd *cobra.Command, args []string) {
		var service_type = viper.GetString("service_type")
		switch service_type {
		case "systemd":
			cmd := exec.Command("systemctl", "status", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		case "sysvinit":
			file, _ := lockfile.New(agentPidFile)
			p, err := file.GetOwner()
			if err != nil {
				fmt.Println("agent is dead")
			} else {
				fmt.Println("agent is running, procs:")
				var pids []int
				var err error
				pids, err = getProcTreeWithCgroup(p.Pid)
				if err != nil {
					pids, _ = getProcTreeWithProc(p.Pid)
				}
				for _, pid := range pids {
					fmt.Println(pid)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
