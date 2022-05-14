module hades-ebpf

replace github.com/chriskaliX/plugin => ../../bridge

go 1.17

require (
	github.com/chriskaliX/plugin v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.8.1
	go.uber.org/zap v1.21.0
)

require (
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/florianl/go-tc v0.4.1 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/mdlayher/netlink v1.6.0 // indirect
	github.com/mdlayher/socket v0.2.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	golang.org/x/net v0.0.0-20220513224357-95641704303c // indirect
	golang.org/x/sync v0.0.0-20220513210516-0976fa681c29 // indirect
)

require (
	github.com/aquasecurity/libbpfgo v0.2.5-libbpf-0.7.0
	github.com/ehids/ebpfmanager v0.2.3
	github.com/evanphx/json-patch v0.5.2
	github.com/goccy/go-json v0.9.7
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/jwangsadinata/go-multimap v0.0.0-20190620162914-c29f3d7f33b6
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/sys v0.0.0-20220513210249-45d2b4557a2a
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
