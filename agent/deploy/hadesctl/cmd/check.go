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

// checkCmd represents the check command
// 区分 service type, 仅当 sysvinit 的时候需要 .pid 作为 lockfile
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "sysvinit" {
			file, _ := lockfile.New(agentPidFile)
			if _, err := file.GetOwner(); err != nil {
				err := sysvinitStart()
				cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
				// https://stackoverflow.com/questions/10193788/restarting-cron-after-changing-crontab-file
				// 一些场景下不一定能用 reload, 需要强制 restart. 是否会导致 crontab 的一些问题? 例如每天重置, 每天不会触发
				// maybe some problems with this restart thing.
				exec.Command("service", "cron", "restart").Run()
				exec.Command("service", "crond", "restart").Run()
				cobra.CheckErr(err)
			} else {
				// TODO: zombie state check
				// 僵尸进程处理
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
