# ePot (HoneyPot Plugin)

> Generally, a honeypot which is widely installed is always struggled with the problem of port occupancy. But eBPF with XDP can help us with this problem.

## Plan

- stream redirect
- security_bind (avoid port confilct)
- flow control

## Dependencies support

- ebpfmanager
    - support sockops in `probe.go`

## Requirements

|Name|Detailed|Module|
|:-:|:-:|:-:|
|cgroup v2| https://github.com/cilium/ebpf/pull/771 | sockops |