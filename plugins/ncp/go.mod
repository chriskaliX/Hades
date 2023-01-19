module ncp

go 1.18

replace github.com/chriskaliX/SDK => ../../SDK/go

require (
	github.com/bytedance/sonic v1.4.0
	github.com/chriskaliX/SDK v1.0.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/vishvananda/netns v0.0.1
	go.uber.org/zap v1.24.0
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448
)

require (
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20211019084208-fb5309c8db06 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/nightlyone/lockfile v1.0.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
)
