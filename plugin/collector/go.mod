module collector

go 1.17

replace github.com/chriskaliX/plugin => ../bridge

require (
	github.com/chriskaliX/plugin v1.0.0
	github.com/cilium/ebpf v0.8.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/vishvananda/netlink v1.1.0
	go.uber.org/zap v1.20.0
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/jinzhu/copier v0.3.5
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	github.com/tklauser/numcpus v0.3.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
