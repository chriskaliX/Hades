module agent

go 1.18

replace github.com/chriskaliX/SDK => ../SDK/go

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/chriskaliX/SDK v1.0.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/gogo/protobuf v1.3.2
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.3.0
	github.com/nightlyone/lockfile v1.0.0
	github.com/shirou/gopsutil/v3 v3.22.8
	go.uber.org/zap v1.23.0
	google.golang.org/grpc v1.51.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

require go.uber.org/atomic v1.7.0 // indirect

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/lufia/plan9stats v0.0.0-20220517141722-cf486979b281 // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20220216144756-c35f1ee13d7c // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.5.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/exp v0.0.0-20221204150635-6dcec336b2bb
	golang.org/x/net v0.1.0 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	google.golang.org/genproto v0.0.0-20220902135211-223410557253 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448
)
