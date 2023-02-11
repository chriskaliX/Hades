module collector

go 1.18

replace github.com/chriskaliX/SDK => ../../SDK/go

require (
	github.com/chriskaliX/SDK v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/shirou/gopsutil v3.21.11+incompatible
	go.uber.org/zap v1.23.0
	golang.org/x/sys v0.4.0
)

require github.com/vishvananda/netlink v1.2.0-beta

require (
	github.com/bytedance/sonic v1.4.0
	github.com/docker/docker v23.0.0+incompatible
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9
	google.golang.org/grpc v1.53.0
	k8s.io/apimachinery v0.25.2
	k8s.io/cri-api v0.26.1
	k8s.io/utils v0.0.0-20220823124924-e9cbc92d1a73
)

require (
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20211019084208-fb5309c8db06 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/moby/term v0.0.0-20221205130635-1aeaba878587 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/nightlyone/lockfile v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gotest.tools/v3 v3.4.0 // indirect
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/jinzhu/copier v0.3.5
	github.com/robfig/cron/v3 v3.0.1
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
)
