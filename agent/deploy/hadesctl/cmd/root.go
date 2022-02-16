/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"fmt"
	"os"

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
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.hadesctl.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".hadesctl" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".hadesctl")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
