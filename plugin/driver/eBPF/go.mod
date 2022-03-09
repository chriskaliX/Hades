module hades-ebpf

replace github.com/chriskaliX/plugin => ../../bridge

go 1.17

require (
	github.com/chriskaliX/plugin v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.8.1
	go.uber.org/zap v1.21.0
)

require (
	github.com/buger/jsonparser v1.1.1
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
