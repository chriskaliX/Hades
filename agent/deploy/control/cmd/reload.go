/*
Copyright © 2022 chriskali
*/
package cmd

import (
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// reloadCmd represents the reload command
var reloadCmd = &cobra.Command{
	Use:   "service-reload",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			// FIXME: https://github.com/systemd/systemd/issues/9467 (old version systemd bug)
			// 看了一下问题主要出现在 reload 之后 watchdog 立马触发了，时间没有重置
			exec.Command("systemctl", "daemon-reload").Run()
		} else if viper.GetString("service_type") == "sysvinit" {
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
		}
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}
