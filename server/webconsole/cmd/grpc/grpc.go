package grpc

import (
	"hboat/api"
	"hboat/cmd/root"
	"hboat/grpc"
	"hboat/pkg/basic"

	"github.com/spf13/cobra"
)

var grpcCommand = &cobra.Command{
	Use:   "grpc",
	Short: "hboat grpc server",
	Long:  `Hboat grpc server launcher`,
	Run:   WebServer,
}

var enableCA bool
var port int
var addr string
var wport int

func init() {
	grpcCommand.PersistentFlags().BoolVar(&enableCA, "ca", false, "enable ca")
	grpcCommand.PersistentFlags().IntVar(&port, "port", 8000, "grpc serve port")
	grpcCommand.PersistentFlags().StringVar(&addr, "addr", "0.0.0.0", "grpc serve address, set to localhost if you need")
	grpcCommand.PersistentFlags().IntVar(&wport, "wport", 8080, "web service listen port")
	root.RootCommand.AddCommand(grpcCommand)
}

// The main function of hboat
func WebServer(command *cobra.Command, args []string) {
	if err := basic.Init(); err != nil {
		panic(err)
	}
	// run grpc and web
	go api.RunGrpcServer(wport)
	grpc.RunWrapper(enableCA, addr, port)
}
