module collector

go 1.17

replace github.com/chriskaliX/plugin => ../bridge

require (
	github.com/chriskaliX/plugin v1.0.0
	github.com/cilium/ebpf v0.8.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/prometheus/procfs v0.7.3
	github.com/vishvananda/netlink v1.1.0
	go.uber.org/zap v1.20.0
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
)

require (
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
)
