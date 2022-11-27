package grpc

import (
	"hboat/cmd/root"
	"hboat/grpc"
	"hboat/server/api"

	"github.com/spf13/cobra"
)

var grpcCommand = &cobra.Command{
	Use:   "grpc",
	Short: "hboat grpc server",
	Long:  `Hboat grpc server launcher`,
	Run:   grpcFunc,
}

var enableCA bool
var port int
var addr string
var wport int

func init() {
	grpcCommand.PersistentFlags().BoolVar(&enableCA, "ca", false, "enable ca")
	grpcCommand.PersistentFlags().IntVar(&port, "port", 8888, "grpc serve port")
	grpcCommand.PersistentFlags().StringVar(&addr, "addr", "0.0.0.0", "grpc serve address, set to localhost if you need")
	grpcCommand.PersistentFlags().IntVar(&wport, "wport", 7811, "grpc web serve port")
	root.RootCommand.AddCommand(grpcCommand)
}

func grpcFunc(command *cobra.Command, args []string) {
	go api.RunGrpcServer(wport)
	grpc.RunWrapper(enableCA, addr, port)
}
