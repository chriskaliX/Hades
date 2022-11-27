package root

import (
	"os"

	"github.com/spf13/cobra"
)

var RootCommand = &cobra.Command{
	Use:   "hboat",
	Short: "Hades server",
}

func Execute() {
	RootCommand.SetHelpTemplate(`{{.UsageString}}`)
	RootCommand.CompletionOptions.DisableDefaultCmd = true
	err := RootCommand.Execute()
	if err != nil {
		os.Exit(1)
	}
}
