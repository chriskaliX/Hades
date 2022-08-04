module hades-ebpf

replace github.com/chriskaliX/plugin => ../../bridge

go 1.17

require (
	github.com/bytedance/sonic v1.3.4
	github.com/chriskaliX/plugin v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.9.1
	github.com/ehids/ebpfmanager v0.3.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/spf13/pflag v1.0.5
	go.uber.org/zap v1.21.0
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9
	k8s.io/apimachinery v0.24.3
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed
)

require (
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20220526154910-8bf9453eb81a // indirect
	github.com/florianl/go-tc v0.4.1 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.1.0 // indirect
	github.com/mdlayher/netlink v1.6.0 // indirect
	github.com/mdlayher/socket v0.2.3 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	golang.org/x/arch v0.0.0-20220722155209-00200b7164a7 // indirect
	golang.org/x/net v0.0.0-20220802222814-0bcc04d9c69b // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
)

require (
	github.com/aquasecurity/libbpfgo v0.3.0-libbpf-0.8.0
	github.com/goccy/go-json v0.9.7 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/sys v0.0.0-20220803195053-6e608f9ce704
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
