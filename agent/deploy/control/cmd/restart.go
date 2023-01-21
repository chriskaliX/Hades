/*
Copyright © 2022 chriskali
*/
package cmd

import (
	"errors"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// restartCmd represents the restart command
var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restart agent",
	Run: func(cmd *cobra.Command, args []string) {
		var service_type = viper.GetString("service_type")
		switch service_type {
		case "systemd":
			cmd := exec.Command("systemctl", "restart", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		case "sysvinit":
			os.RemoveAll(crontabFile)
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			err := sysvinitStop()
			cobra.CheckErr(err)

			err = sysvinitStart()
			cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			cobra.CheckErr(err)
		default:
			cobra.CheckErr(errors.New("service type:" + service_type))
		}
	},
}

func init() {
	rootCmd.AddCommand(restartCmd)
}
