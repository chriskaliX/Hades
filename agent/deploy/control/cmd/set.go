/*
Copyright © 2022 chriskali
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:   "set",
	Short: "set env",
	Run: func(cmd *cobra.Command, args []string) {
		// if usage err
		if cmd.Flags().NFlag() == 0 {
			cobra.CheckErr(cmd.Help())
		}
		cmd.Flags().Visit(
			func(f *pflag.Flag) {
				switch f.Name {
				case "service_type":
					if f.Value.String() != "systemd" && f.Value.String() != "sysvinit" {
						cobra.CheckErr(cmd.Help())
					}
					viper.Set("service_type", f.Value)
				case "id":
					viper.Set("specified_id", f.Value)
					// idc & region are temporary not used, so removed
				}
				cobra.CheckErr(viper.WriteConfig())
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().String("service_type", "", "systemd or sysvinit")
	setCmd.Flags().String("id", "", "id of agent")
}
