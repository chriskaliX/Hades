# tracee

> 学习记录，并且将 tracee 中的部分内容结合我的需求

## hook 点

> 共计 Hook 50 个点, 还有几个 uprobe 的没有, 后续我们会补上。写起来应该不难, 但是要过完所有 hook 点的功能等等

```C
SEC("raw_tracepoint/sys_enter")
SEC("raw_tracepoint/sys_exit")
SEC("raw_tracepoint/sys_execve")
SEC("raw_tracepoint/sys_execveat")
SEC("raw_tracepoint/sys_socket")
SEC("raw_tracepoint/sys_dup")
SEC("raw_tracepoint/sched_process_fork")
SEC("raw_tracepoint/sched_process_exec")
SEC("raw_tracepoint/sched_process_exit")
SEC("raw_tracepoint/sched_switch")
SEC("kprobe/do_exit")
SEC("raw_tracepoint/cgroup_attach_task")
SEC("raw_tracepoint/cgroup_mkdir")
SEC("raw_tracepoint/cgroup_rmdir")
SEC("kprobe/security_bprm_check")
SEC("kprobe/security_file_open")
SEC("kprobe/security_sb_mount")
SEC("kprobe/security_inode_unlink")
SEC("kprobe/commit_creds")
SEC("kprobe/switch_task_namespaces")
SEC("kprobe/cap_capable")
SEC("kprobe/security_socket_create")
SEC("kprobe/security_socket_listen")
SEC("kprobe/security_socket_connect")
SEC("kprobe/security_socket_accept")
SEC("kprobe/security_socket_bind")
SEC("kprobe/udp_sendmsg")
SEC("kprobe/__udp_disconnect")
SEC("kprobe/udp_destroy_sock")
SEC("kprobe/udpv6_destroy_sock")
SEC("raw_tracepoint/inet_sock_set_state")
SEC("kprobe/tcp_connect")
SEC("kprobe/send_bin")
SEC("raw_tracepoint/send_bin_tp")
SEC("kprobe/vfs_write")
SEC("kretprobe/vfs_write")
SEC("kretprobe/vfs_write_tail")
SEC("kprobe/vfs_writev")
SEC("kretprobe/vfs_writev")
SEC("kretprobe/vfs_writev_tail")
SEC("kprobe/security_mmap_addr")
SEC("kprobe/security_file_mprotect")
SEC("raw_tracepoint/sys_init_module")
SEC("kprobe/security_bpf")
SEC("kprobe/security_bpf_map")
SEC("kprobe/security_kernel_read_file")
SEC("kprobe/security_kernel_post_read_file")
SEC("kprobe/security_inode_mknod")

SEC("classifier")
SEC("classifier")
// 为上面两个的备注
SEC("classifier")
int tc_egress(struct __sk_buff *skb) {
    return tc_probe(skb, false);
}

SEC("classifier")
int tc_ingress(struct __sk_buff *skb) {
    return tc_probe(skb, true);
}
```

## 源码摘要

> 前面大部分都是定义, 函数定义, 为后面写 Hook 点做简化。可以看到 Hook 点的代码都很短, 基本用到的函数都被抽象完了。其中有几个地方需要值得注意

### PERCPU_ARRAY & stack 512 bytes 限制

我在初次写 eBPF 的时候, 就想监测 execve 的 Hook 点, 但是能找到的代码里面, 绝大部分的代码都是只挂Hook不读值, 读值的代码都和我第一版的时候一样。每次读一次 args , 就往外 Send 一次。

比如你执行了 `/usr/bin/ls -l -a`, 第一个不算, 也得发送两次报文。当时的疑问是，为什么不能一次发完? 于是我尝试把 args 的值改大：

```C
struct tc_execve_t {
    u64 ts;
    u64 pns;
    u64 cid;
    u32 type;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 gid;
    u32 ppid;
    u32 argsize;
    char filename[FNAME_LEN];
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char args[4000]; // 在这里修改为大值
    char nodename[65];
    char ttyname[64];
    char cwd[40];
};
```

再 make 的时候会发现报错了，错误内容为：

`Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.`

由于 bpf 程序原生并发，如果在用户态尝试拼接 args，在 CPU 核数多的机器上，会是一件比较痛苦的事情。

那么如何突破这个限制呢?在报错里也能看出来，我们需要用到 per-cpu array map 来做大值存储。在 stackoverflow 上搜到一个类似的[问题](https://stackoverflow.com/questions/53627094/ebpf-track-values-longer-than-stack-size)，解决的思路一样，都是运用 per-cpu array map 来规避 stack 512 bytes 的限制，我们看一下 tracee 中的代码实现：

首先看一下 rw_tracepoint/sys_execve 这个 hook 点

```C
SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    ...
    save_str_to_buf(&data, (void *)sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(&data, (const char *const *)sys->args.args[1] /*argv*/, 1);
    ...

    return events_perf_submit(&data, SYS_EXECVE, 0);
}
```

我们的关心点在于，具体是如何运用 per-cpu array 的，即 args[1] 这个地方，我们跟进，顺带展示一下 结构体：

```C
typedef struct event_data {
    struct task_struct *task;
    context_t context;
    void *ctx;
    buf_t *submit_p;
    u32 buf_off;
} event_data_t;
```


```C
static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    // Save argument index
    // 先保存存入的 index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off+1;
    data->buf_off += 2;

    // 展开读取
    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        // 读取不到, 说明读取完了, 跳到 out
        if (!argp)
            goto out;
        // 如果当前的 offset, 不能满足下一次的 read 了, 则退出(上述他的格式的[str1 size][str1], 所以是一个int, 一个最大 STRING_SIZE)
        if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        // submit_p 的数据结构是 buf_t，这个在 tracee 中就是 per-cpu array
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
        data->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)] = elem_num;
    data->context.argnum++;
    return 1;
}
```

最后调用 `events_perf_submit` ，代码如下

```C
static __always_inline int events_perf_submit(event_data_t *data, u32 id, long ret)
{
    data->context.eventid = id;
    data->context.retval = ret;

    // Get Stack trace
    if (get_config(CONFIG_CAPTURE_STACK_TRACES)) {
        int stack_id = bpf_get_stackid(data->ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            data->context.stack_id = stack_id;
        }
    }

    // 在这里把 context 信息带上, 其中 context 就是定义的一些上下文信息, 如 pid, ppid 等等
    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(context_t), &data->context);

    // satisfy validator by setting buffer bounds
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE-1);
    void *output_data = data->submit_p->buf;
    // events 为定义的 PERF_EVENT_ARRAY, 直接将 buf 中的数据输出
    return bpf_perf_event_output(data->ctx, &events, BPF_F_CURRENT_CPU, output_data, size);
}
```