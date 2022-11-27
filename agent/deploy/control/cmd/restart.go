/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// restartCmd represents the restart command
var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "restart", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
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
		}
	},
}

func init() {
	rootCmd.AddCommand(restartCmd)
}
