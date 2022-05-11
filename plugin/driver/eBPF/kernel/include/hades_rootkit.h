/*
 * hades_rookit_detection
 *
 * The methods and codes are mainly based on Elkeid(tyton) and tracee.
 * Mainly, hades detect syscalls, idt and bad eBPF. Also, hooks like
 * do_init_module, security_kernel_read_file, call_usermodehelper are
 * added for general rookit detection.
 */

#ifndef CORE
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/err.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include "define.h"
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

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

    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);
    char *modname = NULL;
    bpf_probe_read_str(&modname, 64 - sizeof(unsigned long), &mod->name);
    save_str_to_buf(&data, &modname, 0);

    // get exe from task
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 1);
    save_pid_tree_to_buf(&data, 12, 2);
    // save file from current task->fs->pwd
    struct fs_struct *file = get_task_fs(data.task);
    if (file == NULL)
        return 0;
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    return events_perf_submit(&data);
}

/*
 * @kernel_read_file:
 *	Read a file specified by userspace.
 *	@file contains the file structure pointing to the file being read
 *	by the kernel.
 *	@id kernel read file identifier
 *	@contents if a subsequent @kernel_post_read_file will be called.
 *	Return 0 if permission is granted.
 */
// In datadog, security_kernel_module_from_file is hooked. But it seems not
// work since it's been removed in kernel version 4.6...
// security_kernel_read_file seems stable and is used by tracee
SEC("kprobe/security_kernel_read_file")
int kprobe_security_kernel_read_file(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = SECURITY_KERNEL_READ_FILE;
    // get the file
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    save_str_to_buf(&data, file_path, 0);

    // get the id
    enum kernel_read_file_id type_id = (enum kernel_read_file_id)PT_REGS_PARM2(ctx);
    save_to_submit_buf(&data, &type_id, sizeof(int), 1);
    return events_perf_submit(&data);
}

// Add rootkit detection just like in Elkeid.
// @Notice: this is under full test
SEC("kprobe/call_usermodehelper")
int kprobe_call_usermodehelper(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = CALL_USERMODEHELPER;
    void *path = (void *)PT_REGS_PARM1(ctx);
    save_str_to_buf(&data, path, 0);
    unsigned long argv = PT_REGS_PARM2(ctx);
    save_str_arr_to_buf(&data, (const char *const *)argv, 1);
    unsigned long envp = PT_REGS_PARM3(ctx);
    // Think twice about this.
    // I do not use `save_envp_to_buf` here, since there is not that much
    // call_usermodehelper called... And since it's very important, it's
    // good to just get them all.
    save_str_arr_to_buf(&data, (const char *const *)envp, 2);
    int wait = PT_REGS_PARM4(ctx);
    save_to_submit_buf(&data, (void *)&wait, sizeof(int), 3);
    // Think twice
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 4);
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
//
// As for as I concerned, things like scan the idt and sys_call_table are
// "positive" action. eBPF progs are more "passive" in anti rootkit.
// We can collect the syscalls from specific probes or ...
// @Reference: https://github.com/pathtofile/bpf-hookdetect/blob/main/src/hookdetect.c

// At last, here is my reference:
// @Reference: https://www.lse.epita.fr/lse-summer-week-2015/slides/lse-summer-week-2015-14-linux_rootkit.pdf
// @Reference: https://github.com/RouNNdeL/anti-rootkit-lkm/blob/14d9f934f7f9a5bf27849c2b51b096fe585bea35/module/anti_rootkit/main.c
// @Reference: https://github.com/JnuSimba/MiscSecNotes/blob/dacdefb60d7e5350a077b135382412cbba0f084f/Linux%E6%B8%97%E9%80%8F/Rootkit%20%E7%BB%BC%E5%90%88%E6%95%99%E7%A8%8B.md
// @Reference: https://blog.csdn.net/dog250/article/details/105371830
// @Reference: https://blog.csdn.net/dog250/article/details/105394840
// @Reference: https://blog.csdn.net/dog250/article/details/105842029
// @Reference: https://he1m4n6a.github.io/2020/07/16/%E5%AF%B9%E6%8A%97rootkits/
// Pre define for all
#define IDT_CACHE 0
#define SYSCALL_CACHE 1
#define IDT_ENTRIES 256
#define MAX_KSYM_NAME_SIZE 64
#define BETWEEN_PTR(x, y, z) (        \
    ((uintptr_t)x >= (uintptr_t)y) && \
    ((uintptr_t)x < ((uintptr_t)y + (uintptr_t)z)))
// CO-RE only since macros not in vmlinux.h
// TODO: need to look into `list_for_each_entry`
#ifdef CORE
#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)
#define list_entry_is_head(pos, head, member) \
    (&pos->member == (head))
#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry(pos, head, member)               \
    for (pos = list_first_entry(head, typeof(*pos), member); \
         !list_entry_is_head(pos, head, member);             \
         pos = list_next_entry(pos, member))

#define MAX_ERRNO 4095
#define unlikely(x) __builtin_expect(!!(x), 0)
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#endif

// Map pre-define, will be moved to define.h
// Just for rename...
static inline bool HADES_IS_ERR_OR_NULL(const void *ptr)
{
    return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

static inline const char *get_kobject_name(const struct kobject *kobj)
{
    return kobj->name;
}

typedef struct ksym_name
{
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;
// https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c
BPF_HASH(ksymbols_map, ksym_name_t, u64, 64);
BPF_HASH(analyze_cache, int, u64, 2);

// get symbol_addr from user_space in /proc/kallsyms
static __always_inline void *get_symbol_addr(char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *)&new_ksym_name);

    if (sym == NULL)
        return 0;

    return *sym;
}
// It's very happy to see https://github.com/aquasecurity/tracee/commit/44c3fb1e6ff2faa42be7285690f7a97990abcb08
// Do a trigger to scan. It's brilliant and I'll go through this and
// do the same thing in Hades. And it's done by @itamarmaouda101
// 2022-04-21: start to review the invoke_print_syscall_table_event function

// The way Elkeid does can not be simply done in eBPF program since the limit of 4096
// under kernel version 5.2. In Elkeid, it always go through the syscalls or idt_entries
// to find any hidden kernel module in this.
// Back to Elkeid anti_rootkit, which is based on https://github.com/nbulischeck/tyton
// detecting syscall_hooks/interrupt_hooks(IDT)/modules/fops(/proc). And I think a BAD
// eBPF program should also be considered.

// Below here is the Elkeid way of anti_rootkit by scanning the syscall_table
// idt_table and ... to get the mod of the function to figure out if it's a 
// hidden module. But this a little bit tricky in eBPF program since the 
// __module_address to the the mod of the address.
// static const char *find_hidden_module(unsigned long addr, event_data_t *data)
// {
//     const char *mod_name = NULL;
//     struct kobject *cur;
//     struct module_kobject *kobj;
//     // get module_kset address
//     char module_kset[12] = "module_kset";
//     unsigned long *kset = (unsigned long *)get_symbol_addr(module_kset);

//     struct kset *mod_kset = (struct kset *)kset;
//     // struct kset *mod_kset = (struct kset *)READ_KERN(module_kset_addr);
//     if (mod_kset == NULL)
//         return NULL;
//     events_perf_submit(data);
// // `list_for_each_entry` should be used here. BUT, again, loop...
// #pragma unroll 256
//     list_for_each_entry(cur, &mod_kset->list, entry)
//     {
//         if (!get_kobject_name(cur))
//             break;
//         kobj = container_of(cur, struct module_kobject, kobj);
//         if (!kobj || !kobj->mod)
//             continue;
//         if (BETWEEN_PTR(addr, kobj->mod->core_layout.base,
//                         kobj->mod->core_layout.size))
//             mod_name = kobj->mod->name;
//     }
//     return mod_name;
// }

// interrupts detection
// static void analyze_interrupts(event_data_t *data)
// {
// #ifdef bpf_target_x86
//     char idt_table[10] = "idt_table";
//     unsigned long *idt_table_addr = (unsigned long *)get_symbol_addr(idt_table);

//     u64 idx = SYSCALL_CACHE;
//     u64 *syscall_num_p;
//     u64 syscall_num;
//     syscall_num_p = bpf_map_lookup_elem(&analyze_cache, (void *)&idx);
//     if (syscall_num_p == NULL)
//         return;
//     syscall_num = (u64)*syscall_num_p;

//     struct module *mod;
//     unsigned long addr;
//     const char *mod_name = "-1";
//     addr = READ_KERN(idt_table_addr[syscall_num]);
//     if (addr == 0)
//         return;
//     mod = (struct module *)addr;
//     if (mod)
//     {
//         mod_name = READ_KERN(mod->name);
//     }
//     else
//     {
//         const char *name = find_hidden_module(addr, data);
//         if (!HADES_IS_ERR_OR_NULL(name))
//         {
//             mod_name = name;
//             save_str_to_buf(data, &name, 0);
//             save_to_submit_buf(data, &syscall_num, sizeof(int), 1);
//             int field = ANTI_ROOTKIT_IDT;
//             save_to_submit_buf(data, &field, sizeof(int), 2);
//             events_perf_submit(data);
//         }
//     }
//     return;
// #endif
// }

// static void analyze_syscalls(event_data_t *data)
// {
//     char syscall_table[15] = "sys_call_table";
//     unsigned long *syscall_table_addr = (unsigned long *)get_symbol_addr(syscall_table);

//     u64 idx = SYSCALL_CACHE;
//     u64 *syscall_num_p;
//     u64 syscall_num;
//     syscall_num_p = bpf_map_lookup_elem(&analyze_cache, (void *)&idx);
//     if (syscall_num_p == NULL)
//         return;
//     syscall_num = (u64)*syscall_num_p;

//     struct module *mod;
//     unsigned long addr = 0;
//     const char *mod_name = "-1";

//     addr = READ_KERN(syscall_table_addr[syscall_num]);
//     if (addr == 0)
//         return;
//     // Can't not use the __module_address API function here. We have to 
//     // a lot of work of this...
//     mod = (struct module *)addr;
//     if (mod)
//     {
//         mod_name = READ_KERN(mod->name);
//     }
//     else
//     {
//         const char *name = find_hidden_module(addr, data);
//         if (!HADES_IS_ERR_OR_NULL(name))
//         {
//             mod_name = name;
//             save_str_to_buf(data, &name, 0);
//             save_to_submit_buf(data, &syscall_num, sizeof(int), 1);
//             int field = ANTI_ROOTKIT_SYSCALL;
//             save_to_submit_buf(data, &field, sizeof(int), 2);
//             events_perf_submit(data);
//         }
//     }
//     return;
// }

#define IOCTL_SCAN_SYSCALLS 65
#define IOCTL_SCAN_IDTS 66

// Below here, Tracee... scan limited syscal_table_addr ...
static __always_inline void sys_call_table_scan(event_data_t *data)
{

    char syscall_table[15] = "sys_call_table";
    unsigned long *syscall_table_addr = (unsigned long *)get_symbol_addr(syscall_table);

    u64 idx = SYSCALL_CACHE;
    u64 *syscall_num_p;
    u64 syscall_num;
    unsigned long syscall_addr = 0;

    syscall_num_p = bpf_map_lookup_elem(&analyze_cache, (void *)&idx);
    if (syscall_num_p == NULL)
        return;
    syscall_num = (u64)*syscall_num_p;
    syscall_addr = READ_KERN(syscall_table_addr[syscall_num]);
    if (syscall_addr == 0)
        return;
    
    save_to_submit_buf(data, &syscall_addr, sizeof(unsigned long), 0);
    save_to_submit_buf(data, &idx, sizeof(u64), 1);

    int field = ANTI_ROOTKIT_SYSCALL;
    save_to_submit_buf(data, &field, sizeof(int), 2);
    events_perf_submit(data);
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(kprobe_security_file_ioctl)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;

    unsigned int cmd = PT_REGS_PARM2(ctx);
    // Skip if not the pid we need
    if (get_config(CONFIG_HADES_PID) != data.context.tid)
        return 0;

    if (cmd == IOCTL_SCAN_SYSCALLS)
    {
        data.context.type = ANTI_ROOTKIT;
        sys_call_table_scan(&data);
    }
    return 0;
}