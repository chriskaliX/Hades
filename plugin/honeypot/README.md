# ePot (HoneyPot Plugin)

> Generally, a honeypot which is widely installed is always struggled with the problem of port occupancy. But eBPF with XDP can help us with this problem.

## Plan

In `ePot`, I wanna hook with both security_bind and XDP(which I haven't lookup into). It may work like this: XDP passes forward the stream, which works fine until security_bind get the port-binding signal(may be occupied by user-space application), then we quit stream re-routing.

It's all just imagination for now. I have not looked into XDP yet. Coming Soon！
