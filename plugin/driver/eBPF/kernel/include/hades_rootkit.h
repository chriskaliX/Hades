#include <linux/module.h>

#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
// TODO: how to deal with rookit that already exists

// Firstly, a rootkit would be loaded into kernel space. There are some
// hooks that we should pay attention to. I get these information from
// Elkeid, and datadog.
// @Reference: https://github.com/DataDog/datadog-agent/blob/aa1665562704cf7505f4be9b95894cd6e68b31f8/pkg/security/ebpf/probes/module.go
// 1. kprobe/do_init_module (this is well-knowned and used in Elkeid)
// 2. kprobe/module_put (@ Reference: https://ph4ntonn.github.io/rootkit%E5%88%86%E6%9E%90-linux%E5%86%85%E6%A0%B8%E6%9C%BA%E5%88%B6%E5%AD%A6%E4%B9%A0)
// There are several things that interest me:
// Firstly, it's the 'module_put' thing. Here is the rootkit that use this function.
// https://github.com/nurupo/rootkit/blob/master/rootkit.c
// We can see that the rootkit use 'try_module_get' in protect function.
// Since in linux, we can not unload a kernel module which gets a non zero
// count. It's nothing new though.
// And a interestring PR from Google to merge the bpf/LSM to kernel, they
// use custom kernel modules as well!
// And other part, like hidden the kernel modules, will be introduced in
// another repo :)

// Firstly, do_init_module is the thing that we need. Any mod that loaded should
// be monitored.
SEC("kprobe/do_init_module")
int kprobe_do_init_module(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1026;
    char nothing[] = "-1";

    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);
    char *modname = NULL;
    int ret = 0;
    bpf_probe_read_str(&modname, 64 - sizeof(unsigned long), &mod->name);
    save_str_to_buf(&data, &modname, 0);

    // get exe from task
    void *exe = get_exe_from_task(data.task);
    ret = save_str_to_buf(&data, exe, 1);
    if (ret == 0)
    {
        save_str_to_buf(&data, nothing, 1);
    }
    save_pid_tree_to_buf(&data, 12, 2);
    // save file from current task->fs->pwd
    struct fs_struct *file;
    bpf_probe_read(&file, sizeof(file), &data.task->fs);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    ret = save_str_to_buf(&data, file_path, 1);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 1);
    }
    return events_perf_submit(&data);
}

// For Hidden Rootkit. It's interestring in Elkeid, let's learn firstly.
// In Elkeid, it's in anti_rootkit file, function `find_hidden_module`
// This reference: (https://www.cnblogs.com/LoyenWang/p/13334196.html)
// helps me understand better.
// Before that, we should have a brief conception of sth.
// IDT(Interrupt Description Table):
//   It's a table shows the relationship
//   of the Interrupt and it's process function. (x86 only)
// sys_call_table:
//   @Reference: https://blog.tofile.dev/2021/07/07/ebpf-hooks.html
//   this article shows the way we do anti rootkit with stack_id. But
//   hook inside kernel(like Reptile), like vfs_read, would be called by
//   other part of the kernel module, so we should determine whether it's
//   right from the stack trace... (interestring)
// core_kernel_text:
//   scan the sys_call_table. If the function did not point to the kernel
//   text section, then it's more likely hooked. Since the text section
//   is stable after the kernel builded.
// kernel sets(ksets):
//    kset contains kobject(s). This reference explains well:
//    https://he1m4n6a.github.io/2020/07/16/%E5%AF%B9%E6%8A%97rootkits/
//    we go through every kobject from the kset and get all kobjs.
//    if the kobject do not exist in the kset
// In Elkeid, the find_hidden_module go through the kobject to judge whether
// it's in the sys_call_table and IDT. And the kernel sets finding is also
// considered. 
//
// In a really brief way, it goes like this. In userspace, we do something
// to trigger the system interrupt.
// It's reasonable that we can do sth with the IDT or the sys_call_table
// to hijack the function. Also for the syscall & sys_enter/exit

// At last, here is my reference:
// @Reference: https://www.lse.epita.fr/lse-summer-week-2015/slides/lse-summer-week-2015-14-linux_rootkit.pdf
// @Reference: https://github.com/RouNNdeL/anti-rootkit-lkm/blob/14d9f934f7f9a5bf27849c2b51b096fe585bea35/module/anti_rootkit/main.c
// @Reference: https://github.com/JnuSimba/MiscSecNotes/blob/dacdefb60d7e5350a077b135382412cbba0f084f/Linux%E6%B8%97%E9%80%8F/Rootkit%20%E7%BB%BC%E5%90%88%E6%95%99%E7%A8%8B.md
// @Reference: https://blog.csdn.net/dog250/article/details/105371830
// @Reference: https://blog.csdn.net/dog250/article/details/105394840
// @Reference: https://blog.csdn.net/dog250/article/details/105842029
// @Reference: https://he1m4n6a.github.io/2020/07/16/%E5%AF%B9%E6%8A%97rootkits/
