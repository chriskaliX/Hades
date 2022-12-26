package cmd

import (
	"fmt"
	"hades-ebpf/user/decoder"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "show events list",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%-30s %s\n\n", "Name", "ID")
		keys := make([]int, 0, len(decoder.Events))
		for k := range decoder.Events {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)
		for _, k := range keys {
			fmt.Printf("%-30s %d\n", decoder.Events[uint32(k)].Name(), k)
		}
		os.Exit(1)
	},
}

func init() {
	RootCmd.AddCommand(listCmd)
}
