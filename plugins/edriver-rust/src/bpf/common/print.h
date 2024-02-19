#ifndef __PRINT_H__
#define __PRINT_H__

#include <missing_definitions.h>
#include <vmlinux.h>
#include "maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

/* size micros */
#define S_U8        sizeof(u8)
#define S_U16       sizeof(u16)
#define S_U32       sizeof(u32)
#define S_U64       sizeof(u64)
#define S_INT       sizeof(int)
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

/* print micros */
#define SBT_CHAR(ctx, c)                                            \
    do {                                                            \
        if (ctx->sbt == NULL)                                       \
            return 0;                                               \
        /* pass verifier */                                         \
        if (ctx->offset > MAX_PERCPU_BUFSIZE - MAX_STR - S_INT)     \
            return 0;                                               \
        int s = bpf_probe_read_str(                                 \
            &(ctx->sbt->buf[ctx->offset + S_INT]),                  \
        MAX_STR, c);                                                \
        if (s == 0)                                                 \
            return 0;                                               \
        if (ctx->offset > MAX_PERCPU_BUFSIZE - S_INT)               \
            return 0;                                               \
        bpf_probe_read(&ctx->sbt->buf[ctx->offset], S_INT, &s);     \
        ctx->offset += (s + S_INT);                                 \
    } while (0)

#define SBT(ctx, ptr, size)                                         \
    do {                                                            \
        if (size == 0)                                              \
            return 0;                                               \
        if (ctx->sbt == NULL)                                       \
            return 0;                                               \
        if (ctx->offset > MAX_PERCPU_BUFSIZE - size)                \
            return 0;                                               \
        if (ctx->offset <= (MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)) {   \
            if (bpf_probe_read(                                     \
                &(ctx->sbt->buf[ctx->offset]), size, ptr) == 0) {   \
                ctx->offset += size;                                \
            }                                                       \
        }                                                           \
    } while(0)

/* report */
static __always_inline int report_event(struct hds_context *ctx)
{
    if (ctx->sbt == NULL)
        return 0;
    return bpf_perf_event_output(ctx->ctx, &events, BPF_F_CURRENT_CPU,
                                 ctx->sbt->buf, (ctx->offset) & MAX_PERCPU_MASK);
}

static __always_inline void *get_percpu_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

#endif