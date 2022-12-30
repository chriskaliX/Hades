module collector

go 1.17

replace github.com/chriskaliX/SDK => ../../SDK/go

require (
	github.com/chriskaliX/SDK v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/shirou/gopsutil v3.21.11+incompatible
	go.uber.org/zap v1.23.0
	golang.org/x/sys v0.0.0-20220405052023-b1e9470b6e64
)

require github.com/vishvananda/netlink v1.2.0-beta

require (
	github.com/bytedance/sonic v1.4.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
)

require (
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20211019084208-fb5309c8db06 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/nightlyone/lockfile v1.0.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9 // indirect
	k8s.io/apimachinery v0.25.2 // indirect
	k8s.io/utils v0.0.0-20220823124924-e9cbc92d1a73 // indirect
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/jinzhu/copier v0.3.5
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/robfig/cron/v3 v3.0.1
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
)
