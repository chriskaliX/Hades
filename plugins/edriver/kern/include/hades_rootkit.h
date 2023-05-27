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
// Reptile captured, "modname":"reptile"
SEC("kprobe/do_init_module")
int BPF_KPROBE(kprobe_do_init_module)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = DO_INIT_MODULE;

    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);
    if (mod == NULL)
        return 0;
    char *modname = NULL;
    bpf_probe_read_str(&modname, 64 - sizeof(unsigned long), &mod->name);
    save_str_to_buf(&data, &modname, 0);

    // get exe from task
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 1);
    save_pid_tree_to_buf_simple(&data, 8, 2);
    // save file from current task->fs->pwd
    struct fs_struct *file = get_task_fs(data.task);
    if (file == NULL)
        return 0;
    void *file_path = get_path_str_simple(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 3);
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
int BPF_KPROBE(kprobe_security_kernel_read_file)
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
// Reptile captured when loaded
// "path":"/bin/bash","argv":"/bin/bash -c /reptile/reptile_start"
SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(kprobe_call_usermodehelper)
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

// At last, here is my references:
// 
// https://www.lse.epita.fr/lse-summer-week-2015/slides/lse-summer-week-2015-14-linux_rootkit.pdf
// https://github.com/RouNNdeL/anti-rootkit-lkm/blob/14d9f934f7f9a5bf27849c2b51b096fe585bea35/module/anti_rootkit/main.c
// https://github.com/JnuSimba/MiscSecNotes/blob/dacdefb60d7e5350a077b135382412cbba0f084f/Linux%E6%B8%97%E9%80%8F/Rootkit%20%E7%BB%BC%E5%90%88%E6%95%99%E7%A8%8B.md
// https://blog.csdn.net/dog250/article/details/105371830
// https://blog.csdn.net/dog250/article/details/105394840
// https://blog.csdn.net/dog250/article/details/105842029
// https://he1m4n6a.github.io/2020/07/16/%E5%AF%B9%E6%8A%97rootkits/

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

// Below here, Tracee... scan limited syscal_table_addr ...
// micros for golang uprobe
#if defined(__TARGET_ARCH_x86)
    #define GO_REG1(x) ((x)->ax)
    #define GO_REG2(x) ((x)->bx)
    #define GO_REG3(x) ((x)->cx)
    #define GO_REG4(x) ((x)->di)
    #define GO_SP(x) ((x)->sp)
#elif defined(__TARGET_ARCH_arm64)
    #define GO_REG1(x) PT_REGS_PARM1(x)
    #define GO_REG2(x) PT_REGS_PARM2(x)
    #define GO_REG3(x) PT_REGS_PARM3(x)
    #define GO_REG4(x) PT_REGS_PARM4(x)
    #define GO_SP(x) PT_REGS_SP(x)
#endif

// 1. syscall hook detection
// Rootkit like https://github.com/m0nad/Diamorphine does hook some syscalls
// like kill
SEC("uprobe/trigger_sct_scan")
int trigger_sct_scan(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = ANTI_RKT_SCT;
    // Hook golang uprobe with eBPF
    // After golang 1.17, params stay at registers (Go internal ABI specification)
    // https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md
    // We only support golang over 1.17, it's fine. When I thought we can easily killed this
    // by get the return value of the function, https://github.com/golang/go/issues/22008
    // returns out it is unsafe to use a uretprobe in golang for now with only static
    // stack assumption.
    //
    // Stack-based is not supported
    unsigned long *address = (unsigned long *) GO_REG2(ctx);
    u64 index = GO_REG3(ctx);
    
    u64 addr = READ_KERN(address[index]);
    // skip if it can not be found in sdt
    if (addr == 0) {
        return 0;
    }

    save_to_submit_buf(&data, &index, sizeof(u64), 0);
    save_to_submit_buf(&data, &addr, sizeof(u64), 1);

    return events_perf_submit(&data);
}

// 2. idt table check (index 0x80 only)
SEC("uprobe/trigger_idt_scan")
int trigger_idt_scan(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1201;
    // Hook golang uprobe with eBPF
    // After golang 1.17, params stay at registers (Go internal ABI specification)
    // https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md
    // We only support golang over 1.17, it's fine. When I thought we can easily killed this
    // by get the return value of the function, https://github.com/golang/go/issues/22008
    // returns out it is unsafe to use a uretprobe in golang for now with only static
    // stack assumption.
    //
    // Stack-based is not supported
    struct gate_struct *gate = (struct gate_struct *) GO_REG2(ctx);
    if (gate == NULL)
        return 0;
    u64 index = GO_REG3(ctx);
    __u16 offset_low;
    bpf_probe_read(&offset_low, sizeof(offset_low), &gate[index].offset_low);
    __u16 offset_middle;
    bpf_probe_read(&offset_middle, sizeof(offset_middle), &gate[index].offset_middle);
    __u32 offset_high;
    bpf_probe_read(&offset_high, sizeof(offset_high), &gate[index].offset_high);
    /* calc the offset */
    u64 idt_addr = offset_low | ((unsigned long)offset_middle << 16) | ((unsigned long)offset_high << 32);
    save_to_submit_buf(&data, &index, sizeof(u64), 0);
    save_to_submit_buf(&data, &idt_addr, sizeof(u64), 0);
    return events_perf_submit(&data);
#else
    return 0;
#endif
}

// filldir/filldir64 detection

#define list_entry(ptr, type, member) \
        container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)

static inline const char *hades_kobject_name(const struct kobject *kobj)
{
	return READ_KERN(kobj->name);
}

BPF_HASH(mod_map, u64, char[64], 512);
/* Trigger module scan
 *
 * It is a limited way to do so. The find_module is kernel API and it's limited,
 * It's much more easier to get the count of available module. We do not get the
 * name, only count is sent to userspace
 * Reptile captured
 *
 * By default, the kernel module in TEXT field, we can findout those not in TEXT
 * field by comparing the address or just find them in /proc/kallsyms
 *
 * https://github.com/carloslack/KoviD, by setting mod->state to MODULE_STATE_UNFORMED
 * And also delete from the memory, trigger_module_scan is evaded, and other part
 * of scanning is evaded too. Let's spend some time to introduce some new 
 * techs to detect this!
 * 
 * And it is easy to bypass this detection, just remember to call kobject_del
 */
SEC("uprobe/trigger_module_scan")
int trigger_module_scan(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = ANTI_RKT_MODULE;

    struct kset *mod_kset = NULL;
	struct kobject *cur = NULL;
	struct module_kobject *kobj = NULL;
    struct list_head list;
	u32 count = 0;
    u32 out = 0;

    // temporary field
    struct list_head tlist;
    struct module *mod;

    mod_kset = (struct kset *)GO_REG2(ctx);
    if (mod_kset == NULL)
		return 0;
    list = READ_KERN(mod_kset->list);
    cur = list_first_entry(&list, typeof(*cur), entry);

    // local bpf way of list_for_each_entry
#pragma unroll
    for (int index = 0; index < 256; index++)
    {
        out = index;
        if (&cur->entry == (&list))
            break;
        tlist = READ_KERN(cur->entry);
        cur = list_entry(tlist.next, typeof(*(cur)), entry);
		if (!hades_kobject_name(cur))
            break;
        kobj = container_of(cur, struct module_kobject, kobj);
        if (kobj == NULL)
            continue;
        mod = READ_KERN(kobj->mod);
        if (mod == NULL)
            continue;
        // For now, we only get the counter for demo, you can
        // implement the find_module to be more accurate
        // But pay attention that name can be easily tampered by a rootkit
        // in struct module, so we do not use any whitelist here...
        count++;
    }
    
    save_to_submit_buf(&data, &out, sizeof(u32), 0);
    save_to_submit_buf(&data, &count, sizeof(u32), 1);
    return events_perf_submit(&data);
}

#define PROC_SUPER_MAGIC       0x9fa0
/* The address of module field can be configurated, as default
 * The kernel module size was pinned to 16M
 * check the elegant way of ADDR
 */ 
#define __AC(X,Y)              (X##Y)
#define _AC(X,Y)               __AC(X,Y)
#define _UL(x)		           (_AC(x, UL))
#define UL(x)                  (_UL(x))
#define HADES_MODULES_VADDR    _AC(0xffffffffa0000000, UL)
#define HADES_MODULES_END      _AC(0xffffffffff000000, UL)
#define HADES_VM_LIMITATION    1 << 18 // just test

/*
 * Compare with /proc/modules
 * Reference: https://unix.stackexchange.com/questions/152507/module-marked-f-in-proc-modules
 * bounded loop seems to be the limitation of the detection method
 * maybe judge the KERNEL_VERSION, remove the unroll part to go through the vmap_area
 * and get the name of the modules
 *
 * spin_lock
 * suspended
 */
// SEC("uprobe/trigger_memory_scan")
// int trigger_memory_scan(struct pt_regs *ctx)
// {
// // #if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 3, 0))
//     event_data_t data = {};
//     if (!init_event_data(&data, ctx))
//         return 0;
//     data.context.type = 1207;

//     struct vmap_area *cur = NULL;
//     struct vm_struct *vm_area = NULL;
//     unsigned long va_start = 0;
//     unsigned long va_end = 0;
//     // vmap_area_list from /proc/kallsyms
//     struct list_head *tlist = (struct list_head *)GO_REG2(ctx);
//     if (tlist == NULL)
//         return 0;

//     cur = list_entry(READ_KERN(tlist->next), typeof(*(cur)), list);
//     // local bpf way of list_for_each_entry
// // #pragma unroll
//     for (int index = 0; index < HADES_VM_LIMITATION; index++)
//     {
//         if (&cur->list == (tlist))
//             break;
//         tlist = GET_FIELD_ADDR(cur->list);
//         cur = list_entry(READ_KERN(tlist->next), typeof(*(cur)), list);
//         if (cur == NULL)
//             continue;
//         va_start = READ_KERN(cur->va_start);
//         va_end = READ_KERN(cur->va_end);
//         vm_area = READ_KERN(cur->vm);
//         // get the start and end, judge the addr area
//         if ((va_start >= HADES_MODULES_VADDR && va_start < HADES_MODULES_END) &&
//             (va_end >= HADES_MODULES_VADDR && va_end < HADES_MODULES_END) && (vm_area != NULL)) {
//                 // module point to itself, and find
//                 // go range from start to end by page, 
//                 // check the module self pointer with container_of

//                 for (unsigned long address = va_start; address < va_end; address += sizeof(unsigned long)) {
//                     // for test, just get the size
//                     // how to work like container_of...
//                     // char *name = READ_KERN(m->name);
//                     // save_to_submit_buf(&data, &name, 16, 0);
//                     //
//                     // Just test code
//                     struct module *m = container_of(address, struct module, syms);
//                     if (m == NULL)
//                         continue;

//                     save_to_submit_buf(&data, &va_start, sizeof(unsigned long), 0);
//                     events_perf_submit(&data);
//                 }
//             }
//     }
// // #endif
//     return 0;
// }

/* 3. fops checks
 * In tracee, security_file_permission is hooked for file
 * file_operations iterater detection, but in tyton(or Elkeid)
 * only detect the /proc dir, which may be evaded. There are
 * more than one way to hide from the proc file, set SUSPEND
 * flag just like Reptile do can also evade detection like
 * this one. PAY ATTENTION TO list kernel
 * 
 * Reference:
 * https://vxug.fakedoma.in/papers/h2hc/H2HC%20-%20Matveychikov%20&%20f0rb1dd3%20-%20Kernel%20Rootkits.pdf
 * tracee: https://blog.aquasec.com/detect-drovorub-kernel-rootkit-attack-tracee
 * rootkit-demo: https://github.com/Unik-lif/rootkit-hide
 * evasion: https://blog.csdn.net/dog250/article/details/105939822
 *
 * Warning: This function is under full test, PERFORMANCE IS UNKNOWN
 * from tracee. filldir
 */

SEC("kprobe/security_file_permission")
int BPF_KPROBE(kprobe_security_file_permission)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == NULL)
        return 0;
    struct inode *f_inode = READ_KERN(file->f_inode);
    struct super_block *i_sb = READ_KERN(f_inode->i_sb);
    unsigned long s_magic = READ_KERN(i_sb->s_magic);

    if (s_magic != PROC_SUPER_MAGIC) {
        return 0;
    }

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = ANTI_RKT_FOPS;

    struct file_operations *fops = (struct file_operations *) READ_KERN(f_inode->i_fop);
    if (fops == NULL)
        return 0;

    // kernel version 4.10 iterate_shared
    unsigned long iterate_shared_addr = (unsigned long) READ_KERN(fops->iterate_shared);
    unsigned long iterate_addr = (unsigned long) READ_KERN(fops->iterate);
    
    if (iterate_shared_addr == 0 && iterate_addr == 0)
        return 0;
    
    // get configuration from bpf_map, if not contained, skip
    u64 *stext = get_config(STEXT);
    u64 *etext = get_config(ETEXT);
    if (stext == NULL || etext == NULL)
        return 0;

    // Add detections for module address
    // In tracee, the address is checked in userspace from _stext to _etext
    // more details about memory
    // https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
    // It's ok to use the hook check for kernel text section or the module addr sec
    // for now, we just hardcode those, for experimental
    // 
    // for now, we do not use MODULE_VADDR, since we need to get this address from
    // userspace also.
    if (iterate_shared_addr > 0) {
        if (iterate_shared_addr >= *stext && iterate_shared_addr <= *etext) {
            return 0;
        }
    }
    if (iterate_addr > 0) {
        if (iterate_addr >= *stext && iterate_addr <= *etext) {
            return 0;
        }
    }

    save_to_submit_buf(&data, &iterate_shared_addr, sizeof(u64), 0);
    save_to_submit_buf(&data, &iterate_addr, sizeof(u64), 1);
    return events_perf_submit(&data);
}
// 4. net check

// 5. eBPF backdoor(behavior) detection
// https://github.com/kris-nova/boopkit
// eBPF-based rootkit(detection), upload an eBPF program's behavior
// Related kernel functions are here:
// security_bpf(__sys_bpf from SYSCALL, very early stage)
// bpf_check (verifier) => https://elixir.bootlin.com/linux/v6.0/source/kernel/bpf/verifier.c#L15128
// security_bpf_prog(within bpf_prog_new_fd, after bpf_check)
// 
// According to the https://github.com/Gui774ume/ebpfkit-monitor, I simplify this by following:
// 1. kprobe/sys_bpf for initialization
// 2. security_bpf, only recording cmd like
//    BPF_PROG_LOAD/BPF_PROG_ATTACH/BPF_BTF_LOAD/BPF_RAW_TRACEPOINT_OPEN, but we won't do a filter
//    for now, since we also hook security_bpf_prog
// 3. security_bpf_prog, get the context information about the program
// 4. kpretprobe/sys_bpf for popping the result to userspace
//
// Event more, we could block the way to initialize, override the return by
// bpf_override_return(ctx, -EPERM);
// to block. But, be really careful about this action. And, like anti-rootkit part
// we should also add behavior detection instead of doing stack trace...
// 
// Reference:
// https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf
// TODO: in ubuntu, sometimes hook failed
// remove temporary
// #define EPERM 1
// SEC("kprobe/bpf")
// int BPF_KPROBE(kprobe_sys_bpf)
// {
//     // Be careful about access to bpf_map and change value directly
//     event_data_t data = {};
//     if (!init_event_data(&data, ctx))
//         return 0;
//     if (context_filter(&data.context))
//         return 0;
//     if (get_config(DENY_BPF) == 0)
//         return 0;
//     return bpf_override_return(ctx, -EPERM);
// }

// SEC("kprobe/security_bpf")
// int BPF_KPROBE(kprobe_security_bpf)
// {
//     event_data_t data = {};
//     if (!init_event_data(&data, ctx))
//         return 0;
//     if (context_filter(&data.context))
//         return 0;
//     data.context.type = SYS_BPF;
//     void *exe = get_exe_from_task(data.task);
//     save_str_to_buf(&data, exe, 0);
//     // command
//     int cmd = PT_REGS_PARM1(ctx);
//     save_to_submit_buf(&data, &cmd, sizeof(int), 1);
//     switch (cmd) {
//     case BPF_PROG_LOAD: {
//         union bpf_attr *attr = (union bpf_attr *)PT_REGS_PARM2(ctx);
//         if (attr == NULL)
//             return 0;
//         char *name = READ_KERN(attr->prog_name);
//         save_str_to_buf(&data, name, 2);
//         u32 type = READ_KERN(attr->prog_type);
//         save_to_submit_buf(&data, &type, sizeof(u32), 3);
//         return events_perf_submit(&data);
//     }
//     default:
//         return 0;
//     }
// }

// https://blog.csdn.net/dog250/article/details/105465553
/* Hardcode memory scan
 * How this works? Scan the whole .text section, find anything that
 *
 * detect demo:
 * https://github.com/sysprog21/lkm-hidden
 * just work like dog250's blog: https://blog.csdn.net/dog250/article/details/106064940
 * it removes itself from a lot of list including kmod->list, so that there
 * is no chance that tyton or Elkeid can detect this.
 */

/* Other references:
 * https://www.acsac.org/2004/papers/99.pdf
 */