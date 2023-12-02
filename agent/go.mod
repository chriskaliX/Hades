module github.com/chriskaliX/Hades/agent

go 1.19

replace github.com/chriskaliX/SDK => ../SDK/go

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/chriskaliX/SDK v1.0.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.3.0
	github.com/nightlyone/lockfile v1.0.0
	github.com/shirou/gopsutil/v3 v3.23.2
	go.uber.org/zap v1.24.0
	google.golang.org/grpc v1.54.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require go.uber.org/atomic v1.10.0 // indirect

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/lufia/plan9stats v0.0.0-20230110061619-bbe2e5e100de // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20221212215047-62379fc7944b // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	google.golang.org/genproto v0.0.0-20230322174352-cde4c949918d // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	k8s.io/utils v0.0.0-20230313181309-38a27ef9d749
)
