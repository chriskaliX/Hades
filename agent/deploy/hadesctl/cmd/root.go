/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

const (
	serviceName = "hades-agent"
	// systemd service file
	serviceFile  = "/etc/hades/hades-agent.service"
	agentWorkDir = "/etc/hades/"
	agentFile    = "/etc/hades/hades-agent"
	// pid 文件作用防止进程启动多个副本, 只有获得特定 pid 的写入权限的进程才能正常启动(F_WRLCK)
	// 在 Elkeid 中在 check 中, 但事实上也没有什么特殊的规则, 只是简单的约定
	// https://stackoverflow.com/questions/8296170/what-is-a-pid-file-and-what-does-it-contain
	agentPidFile   = "/var/run/hades-agent.pid"
	cgroupPath     = "/hades-agent"
	crontabContent = "* * * * * root /etc/hades/hadesctl check\n"
	crontabFile    = "/etc/cron.d/hades-agent"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "hadesctl",
	Short: "hadesctl to control your hades-agent",
	Long:  `hades agent to control your hades-agent`,
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigFile(cfgFile)
	viper.SetConfigType("props")
	// If a config file is found, read it in.
	viper.ReadInConfig()
}
