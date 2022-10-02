package cmd

import (
	"hades-ebpf/user/share"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:     "ebpfdriver",
	Version: "v1.0.2",
}

var Debug bool

func Execute() {
	RootCmd.SetHelpTemplate(`{{.UsageString}}`)
	RootCmd.CompletionOptions.DisableDefaultCmd = true
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.EnablePrefixMatching = true
	RootCmd.PersistentFlags().BoolVar(&Debug, "debug", false, "set true send output to console")
	RootCmd.Flags().StringSliceVarP(&share.EventFilter, "filter", "f", []string{}, "set filters, like 1203,1201")
}
