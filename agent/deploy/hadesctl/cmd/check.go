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
			_, err := file.GetOwner()
			if err != nil {
				err := sysvinitStart()
				cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// checkCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// checkCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
