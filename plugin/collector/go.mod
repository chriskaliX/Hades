module collector

go 1.17

replace github.com/chriskaliX/SDK => ../../SDK

require (
	github.com/chriskaliX/SDK v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/shirou/gopsutil v3.21.11+incompatible
	go.uber.org/zap v1.21.0
	golang.org/x/sys v0.0.0-20220405052023-b1e9470b6e64
)

require github.com/vishvananda/netlink v1.2.0-beta

require (
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/jinzhu/copier v0.3.5
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
