/*
Copyright © 2022 chriskali
*/
package cmd

import (
	"errors"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// reloadCmd represents the reload command
var reloadCmd = &cobra.Command{
	Use:   "service-reload",
	Short: "reload service",
	Run: func(cmd *cobra.Command, args []string) {
		var service_type = viper.GetString("service_type")
		switch service_type {
		case "systemd":
			// https://github.com/systemd/systemd/issues/9467
			// In short: Watchdog timeout triggered right upon running
			// systemctl daemon-reload
			//
			// The fix-up here, just remove the watchdogsec from .service
			// which is already done.
			exec.Command("systemctl", "daemon-reload").Run()
		case "sysvinit":
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
		default:
			cobra.CheckErr(errors.New("service type:" + service_type))
		}
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}
