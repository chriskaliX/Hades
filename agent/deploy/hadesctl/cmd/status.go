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
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "status", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
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
		} else if viper.GetString("service_type") == "" {
			fmt.Println("service_type not set")
		} else {
			fmt.Println("unknown service_type: ", viper.GetString("service_type"))
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
