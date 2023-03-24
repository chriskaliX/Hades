module collector

go 1.19

replace (
	github.com/chriskaliX/SDK => ../../SDK/go
)

require (
	github.com/chriskaliX/SDK v1.0.0
	github.com/fsnotify/fsnotify v1.6.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/shirou/gopsutil v3.21.11+incompatible
	go.uber.org/zap v1.24.0
	golang.org/x/sys v0.6.0
)

require github.com/vishvananda/netlink v1.2.1-beta.2

require (
	github.com/bytedance/sonic v1.8.3
	github.com/cilium/ebpf v0.10.0
	github.com/coreos/go-iptables v0.6.0
	github.com/docker/docker v23.0.1+incompatible
	github.com/go-ping/ping v1.1.0
	github.com/shirou/gopsutil/v3 v3.23.2
	golang.org/x/time v0.3.0
	google.golang.org/grpc v1.53.0
	k8s.io/apimachinery v0.26.2
	k8s.io/cri-api v0.26.0-alpha.2
	k8s.io/utils v0.0.0-20230220204549-a5ecb0141aa5
)

require (
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/moby/term v0.0.0-20221205130635-1aeaba878587 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/nightlyone/lockfile v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20221212215047-62379fc7944b // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20230303212802-e74f57abe488 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gotest.tools/v3 v3.4.0 // indirect
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/godbus/dbus/v5 v5.1.0
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/robfig/cron/v3 v3.0.1
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/exp v0.0.0-20230304125523-9ff063c70017
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)
