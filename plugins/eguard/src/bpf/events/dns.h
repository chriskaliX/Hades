/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vmlinux.h"
#include "define.h"
#include "utils.h"
#include "utils_buf.h"
#include "rules/acl.h"
#include "common/general.h"

struct udpdata
{
    int opcode;
    int rcode;
    int qtype; // dns: question type. 1 - A; 5 - cname; 28 - AAAA...
    int atype; // dns: answer(rr) type. 1 - A; 5 - cname; 28 - AAAA... [just get first rr type]
};

static __always_inline int dns_resolve(void *ctx, struct sock *sk, struct msghdr *msg)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.dt = 3201;

    // handle the udp send package
    int ret = 0;
    struct iov_iter msg_iter = {0};
    struct iovec iov;

    msg_iter = READ_KERN(msg->msg_iter);
    ret = bpf_probe_read(&iov, sizeof(iov), msg_iter.iov);
    if (ret != 0)
        return 0;
    unsigned long iov_len = iov.iov_len;
    if (iov_len < 20)
        return 0;
    // truncated here, do not drop, as in dns
    if (iov_len > 512)
        iov_len = 512;
    // Firstly, we need to understand the dns data struct
    // The reference is here: http://c.biancheng.net/view/6457.html
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return 0;
    // clear the comm
    bpf_probe_read(&(string_p->buf[0]), iov_len & (512), iov.iov_base);
    // The data structure of dns is here...
    // |SessionID(2 bytes)|Flags(2 bytes)|Data(8 bytes)|Querys...|
    // The datas that we need are flags & querys
    int qr = (string_p->buf[2] & 0x80) ? 1 : 0;
    // 0 stands for dns requests
    if (qr == 1)
        return 0;
    int opcode = (string_p->buf[2] >> 3) & 0x0f;
    int rcode = string_p->buf[3] & 0x0f;
    struct udpdata udata = {};
    udata.opcode = opcode;
    udata.rcode = rcode;

    int len;
    int templen;
    int end_flag = 0; // end_flag: question domain parse finished
#pragma unroll
    for (int i = 0; i < 10; i++)
    {
        // firstly get the length
        if (i == 0)
        {
            len = string_p->buf[12];
            len = 12 + len;
        }
        else
        {
            templen = string_p->buf[(len + 1) & (MAX_PERCPU_BUFSIZE - 1)];
            if (templen == 0)
            {
                end_flag = 1;
                break;
            }
            string_p->buf[(len + 1) & (MAX_PERCPU_BUFSIZE - 1)] = 46;
            len = len + templen + 1;
        }
    }

    // bad case: we hav't finished domain parse
    if (end_flag == 1) {
        udata.qtype =  string_p->buf[(len + 3) & (MAX_PERCPU_BUFSIZE - 1)] | \
                string_p->buf[(len + 2) & (MAX_PERCPU_BUFSIZE - 1)]; 
        udata.atype =  string_p->buf[(len + 5 + 3) & (MAX_PERCPU_BUFSIZE - 1)] | \
                string_p->buf[(len + 5 + 4) & (MAX_PERCPU_BUFSIZE - 1)];
    } else { // bad case: default val
        udata.qtype = 0;
        udata.atype = 0;
    }

    // Convert the domain partly, for example:
    // thisittest.www.googole.com -> com.google.thisistest
    // Then use the lpm to find the root address of what we care, and compitable
    // to .com and .com.cn or something like this.
    // record as much as 4 to backforward match by lpm
    save_str_to_buf(&data, (void *)&string_p->buf[13], 1);
    return events_perf_submit(&data);
}