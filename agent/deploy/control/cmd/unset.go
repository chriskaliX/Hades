/*
Copyright © 2022 chriskali

*/
package cmd

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func unset(key string) error {
	configMap := viper.AllSettings()
	delete(configMap, key)
	buf := bytes.NewBuffer(nil)
	for k, v := range configMap {
		fmt.Fprintf(buf, "%v = %v", k, v)
	}
	err := viper.ReadConfig(buf)
	if err != nil {
		return err
	}
	return viper.WriteConfig()
}

// unsetCmd represents the unset command
var unsetCmd = &cobra.Command{
	Use:   "unset",
	Short: "unset env",
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.Flags().NFlag() == 0 {
			cobra.CheckErr(cmd.Help())
		}
		cmd.Flags().Visit(
			func(f *pflag.Flag) {
				switch f.Name {
				case "service_type":
					unset("service_type")
				case "id":
					unset("id")
				default:
					fmt.Println("unsupport service_type:", f.Name)
				}
				cobra.CheckErr(viper.WriteConfig())
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(unsetCmd)
}
