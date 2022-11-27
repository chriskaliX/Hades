/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"os"
	"os/exec"

	"github.com/nightlyone/lockfile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for sysvinit",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "sysvinit" {
			file, _ := lockfile.New(agentPidFile)
			if _, err := file.GetOwner(); err == nil {
				err := sysvinitStart()
				cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
				exec.Command("service", "cron", "restart").Run()
				exec.Command("service", "crond", "restart").Run()
				cobra.CheckErr(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
