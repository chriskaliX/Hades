module agent

go 1.16

replace github.com/chriskaliX/SDK => ../SDK

require (
	cloud.google.com/go/compute v1.9.0 // indirect
	github.com/StackExchange/wmi v1.2.1
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/chriskaliX/SDK v1.0.0
	github.com/cncf/udpa/go v0.0.0-20220112060539-c52dc94e7fbe // indirect
	github.com/cncf/xds/go v0.0.0-20220520190051-1e77728a1eaa // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/envoyproxy/go-control-plane v0.10.3 // indirect
	github.com/gogo/protobuf v1.3.2
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/lufia/plan9stats v0.0.0-20220517141722-cf486979b281 // indirect
	github.com/nightlyone/lockfile v1.0.0
	github.com/power-devops/perfstat v0.0.0-20220216144756-c35f1ee13d7c // indirect
	github.com/shirou/gopsutil/v3 v3.22.8
	github.com/tklauser/numcpus v0.5.0 // indirect
	go.uber.org/atomic v1.10.0
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.23.0
	golang.org/x/net v0.0.0-20220826154423-83b083e8dc8b // indirect
	golang.org/x/oauth2 v0.0.0-20220822191816-0ebed06d0094 // indirect
	golang.org/x/sys v0.0.0-20220829200755-d48e67d00261 // indirect
	google.golang.org/genproto v0.0.0-20220902135211-223410557253 // indirect
	google.golang.org/grpc v1.49.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
