package grpc

import (
	"hboat/cmd/root"
	"hboat/pkg"
	"hboat/pkg/api"
	"hboat/pkg/config"
	"hboat/pkg/datasource"
	"hboat/pkg/grpc"

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
	grpcCommand.PersistentFlags().IntVar(&port, "port", 8888, "grpc serve port")
	grpcCommand.PersistentFlags().StringVar(&addr, "addr", "0.0.0.0", "grpc serve address, set to localhost if you need")
	grpcCommand.PersistentFlags().IntVar(&wport, "wport", 7811, "web service listen port")
	root.RootCommand.AddCommand(grpcCommand)
}

// The main function of hboat
func WebServer(command *cobra.Command, args []string) {
	// init the datasources
	if err := datasource.NewMongoDB(config.MongoURI, 5); err != nil {
		panic(err)
	}
	if err := datasource.NewRedisClient(
		config.RedisAddrs,
		config.RedisMasterName,
		config.RedisPassword,
		config.RedisMode); err != nil {
		panic(err)
	}
	// init user admin
	if err := pkg.UserInit(); err != nil {
		panic(err)
	}

	// run grpc and web
	go api.RunGrpcServer(wport)
	grpc.RunWrapper(enableCA, addr, port)
}
