package collector

// ebpf 的采集
// 大致逻辑为: 写一段代码让内核 load
// 因为 ebpf 有 DAG check & Execution Simulation Check
// 并且限制了 limit 4096, 较为安全
// 还没看完, 重点关注 kprobe, 参考一下 osquery (新版本已经引入 ebpf 了)
// osquery 的 ebpf 相关地址 https://github.com/osquery/osquery/tree/d2be385d71f401c85872f00d479df8f499164c5a/osquery/events/linux/bpf

