#include "hades_exec.h"
#include "hades_net.h"
#include "hades_privilege.h"
#include "hades_rootkit.h"
#include "hades_file.h"
#include "hades_uprobe.h"
#include "hades_honeypot.h"

// cat /sys/kernel/debug/kprobes/list to observe the points we've hooked
// all is from tracee & some from datadog-agent, I do some modification though!!!

__u32 _version SEC("version") = 0xFFFFFFFE;
char LICENSE[] SEC("license") = "GPL";
