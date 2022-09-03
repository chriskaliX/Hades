module agent

go 1.16

replace github.com/chriskaliX/SDK => ../SDK

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/chriskaliX/SDK v1.0.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/gogo/protobuf v1.3.2
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/shirou/gopsutil/v3 v3.22.7
	go.uber.org/atomic v1.10.0
	go.uber.org/zap v1.23.0
	google.golang.org/grpc v1.49.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
