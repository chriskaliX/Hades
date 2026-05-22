#include "probes/process_exec.h"
#include "probes/process_exploit.h"
#include "probes/process_file.h"
#include "probes/process_net.h"
#include "probes/process_privilege.h"
#include "probes/process_rootkit.h"
#include "probes/process_honeypot.h"
#include "probes/process_uprobe.h"

__u32 _version SEC("version") = 0xFFFFFFFE;
char LICENSE[] SEC("license") = "GPL";
