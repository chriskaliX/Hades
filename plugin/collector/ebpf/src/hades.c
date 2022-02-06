#include "hades_exec.h"
#include "hades_net.h"
#include "hades_privilege.h"

// cat /sys/kernel/debug/kprobes/list to observe the points we've hooked
// all is from tracee & some from datadog-agent, I do some modification though!!!

__u32 _version SEC("version") = 0xFFFFFFFE;
char LICENSE[] SEC("license") = "GPL";
