// For uprobe, here are things that I want!
// uprobe is really useful, we can use this in lower kernel version. Since
// re-location is not needed, CO-RE seems not that important...
#include "define.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// in Cilium example, the size of the line is limited to 80, we enlarge this to 256
// SEC("uretprobe/bash_readline")
// int uretprobe_bash_readline(struct pt_regs *ctx)
// {
//     event_data_t data = {};
//     if (!init_event_data(&data, ctx))
//         return 0;
//     data.context.type = BASH_READLINE;
//     // exe
//     void *exe = get_exe_from_task(data.task);
//     save_str_to_buf(&data, exe, 0);
//     // line
//     void *line = (void *)PT_REGS_RC(ctx);
//     save_str_to_buf(&data, line, 1);
//     void *ttyname = get_task_tty_str(data.task);
//     save_str_to_buf(&data, ttyname, 2);
//     // stdin
//     void *stdin = get_fraw_str(0);
//     save_str_to_buf(&data, stdin, 3);
//     // stdout
//     void *stdout = get_fraw_str(1);
//     save_str_to_buf(&data, stdout, 4);
//     // socket
//     get_socket_info(&data, 5);
//     // add pid_tree to the field
//     save_pid_tree_to_buf(&data, 8, 6);
//     struct fs_struct *file = get_task_fs(data.task);
//     if (file == NULL)
//         return 0;
//     void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
//     save_str_to_buf(&data, file_path, 7);
//     return events_perf_submit(&data);
// }

// probe the java thing
// nm -D /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server/libjvm.so
// what we should pay attention to is the syscalls and some JVM_<function>
// BTW, hook points like JVM_InvokeMethod is easy, but we can not get the
// stack information by just hooking it.
// Actually, kprobes/tracepoints we done before are good enough to capture
// all behavior we need. Just like the thing from uprobe/bash_readline,
// we can already get then all in execve or some other points (but in a
// raw way)
// And uprobe (maybe, I have not checked yet) can be used in kernel version
// lower 4.18, above 3.18 (maybe). The way we used in k(ret)probe/uprobe,
// the pt_regs, seems to be used in kernel > 4.17. We need to change the
// format.
// SEC("uprobe/JVM_GC")
// int uprobe_JVM_GC(struct pt_regs *ctx)
// {
//     event_data_t data = {};
//     if (!init_event_data(&data, ctx))
//         return 0;
//     data.context.type = 2001;
//     return events_perf_submit(&data);
// }