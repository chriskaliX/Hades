/*
Copyright © 2022 chriskali
Generate: cobra add disable --author chriskali --viper
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

// disableCmd represents the disable command
var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "disable agent",
	Long:  `disable agent by systemd/sysvinit`,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "disable", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
			// higher kernel version, update-rc.d used
			if _, err := exec.LookPath("update-rc.d"); err == nil {
				res, err := exec.Command("update-rc.d", "-f", serviceName, "remove").CombinedOutput()
				if err != nil {
					cobra.CheckErr(fmt.Errorf("%w: %v", err, string(res)))
				}
				return
			}
			// in lower kernel version, chkconfig used
			if _, err := exec.LookPath("chkconfig"); err == nil {
				res, err := exec.Command("chkconfig", "--del", serviceName).CombinedOutput()
				if err != nil {
					cobra.CheckErr(fmt.Errorf("%w: %v", err, string(res)))
				}
				return
			}
			cobra.CheckErr(errors.New("no available service management tool"))
		}
	},
}

func init() {
	rootCmd.AddCommand(disableCmd)
}
