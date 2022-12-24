package cmd

import (
	"hades-ebpf/user/share"
	"os"

	"github.com/spf13/cobra"
)

// TODO: version tag
var RootCmd = &cobra.Command{
	Use:     "ebpfdriver",
	Version: "v1.1.0",
}

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
	RootCmd.PersistentFlags().BoolVar(&share.Debug, "debug", false, "set true send output to console")
	RootCmd.Flags().StringSliceVarP(&share.EventFilter, "filter", "f", []string{}, "set filters, like 1203,1201")
}
