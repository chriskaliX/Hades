# Hades

English | [中文](README-zh_CN.md)

Hades is a Host-based Intrusion Detection System based on both eBPF and Netlink/cn_proc. Now it's still under development. PRs and issues are welcomed!

This project is based on [Tracee](https://github.com/aquasecurity/tracee) and [Elkeid](https://github.com/bytedance/Elkeid). Thanks for these awesome open-source projects.

## Architecture

> Agent part is mainly based on [Elkeid](https://github.com/bytedance/Elkeid) version 1.7. And I am gonna make plugin/driver compatible for Elkeid.

### Agent Part

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/agent.png)

### Data Analysis

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/data_analyze.png)

## Plugins

- [Driver-eBPF](https://github.com/chriskaliX/Hades/tree/main/plugin/driver/eBPF)
- [Collector](https://github.com/chriskaliX/Hades/tree/main/plugin/collector)
- HoneyPot
- Monitor
- Scanner
- Logger

## Capability

> Here are 15 hooks over `tracepoints`/`kprobes`/`uprobes`. The fields are extended just like Elkeid(basically).

For [details](https://github.com/chriskaliX/Hades/tree/main/plugin/driver) of these hooks.

## Purpose

I maintain this project mainly for learning eBPF and HIDS

## Contact

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/WechatIMG120.jpeg" width="50%" style="float:left;"/>
