/*
Copyright © 2022 chriskali
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgFile     = "/etc/hades/specified_env"
	serviceName = "hades-agent"
	// systemd service file
	serviceFile    = "/etc/hades/hades-agent.service"
	agentWorkDir   = "/etc/hades/"
	agentFile      = "/etc/hades/hades-agent"
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
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
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
