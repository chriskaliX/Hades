/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// enableCmd represents the enable command
var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "enable agent",
	Long:  `enable agent by systemd/sysvinit`,
	Run: func(cmd *cobra.Command, args []string) {
		var service_type = viper.GetString("service_type")
		switch service_type {
		case "systemd":
			cmd := exec.Command("systemctl", "enable", serviceFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		case "sysvinit":
			_, err := exec.LookPath("update-rc.d")
			if err == nil {
				res, err := exec.Command("update-rc.d", serviceName, "defaults").CombinedOutput()
				if err != nil {
					cobra.CheckErr(fmt.Errorf("%w: %v", err, string(res)))
				}
				return
			}
			_, err = exec.LookPath("chkconfig")
			if err == nil {
				res, err := exec.Command("chkconfig", "--add", serviceName).CombinedOutput()
				if err != nil {
					cobra.CheckErr(fmt.Errorf("%w: %v", err, string(res)))
				}
				return
			}
			cobra.CheckErr(errors.New("no available service management tool"))
		default:
			cobra.CheckErr(errors.New("service type:" + service_type))
		}
	},
}

func init() {
	rootCmd.AddCommand(enableCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// enableCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// enableCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
