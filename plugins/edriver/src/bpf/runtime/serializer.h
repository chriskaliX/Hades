#ifndef __RUNTIME_SERIALIZER_H__
#define __RUNTIME_SERIALIZER_H__

#include <missing_definitions.h>
#include <vmlinux.h>
#include "maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

/* upper bound for _EVT_WRITE_BYTES bounds check */
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

/*
 * _EVT_WRITE_STR  — string path: [sizeof(int) len][string data]
 * _EVT_WRITE_BYTES — bytes path: raw bpf_probe_read of src_size bytes
 *
 * Both are internal; probes use EVT_WRITE or EVT_SUBMIT.
 */
#define _EVT_WRITE_STR(ctx, src_ptr)                                         \
    do {                                                                     \
        if ((ctx)->sbt == NULL)                                              \
            return 0;                                                        \
        u32 _woff = ((u32)((ctx)->offset)) & MAX_PERCPU_MASK;               \
        if (_woff > (MAX_PERCPU_BUFSIZE - MAX_STR - sizeof(int)))            \
            return 0;                                                        \
        int _ssz = bpf_probe_read_str(                                       \
            &((ctx)->sbt->buf[_woff + sizeof(int)]),                         \
            MAX_STR,                                                         \
            (src_ptr));                                                      \
        if (_ssz <= 0 || _ssz > MAX_STR)                                     \
            return 0;                                                        \
        if ((_woff + (u32)_ssz + sizeof(int)) > MAX_PERCPU_BUFSIZE)         \
            return 0;                                                        \
        bpf_probe_read(&((ctx)->sbt->buf[_woff]), sizeof(int), &_ssz);       \
        (ctx)->offset = (_woff + (u32)_ssz + sizeof(int)) & MAX_PERCPU_MASK; \
    } while (0)

#define _EVT_WRITE_BYTES(ctx, src_ptr, src_size)                             \
    do {                                                                     \
        u32 _wsz = (u32)(src_size);                                          \
        if (_wsz == 0)                                                       \
            return 0;                                                        \
        if ((ctx)->sbt == NULL)                                              \
            return 0;                                                        \
        if ((ctx)->offset > (MAX_PERCPU_BUFSIZE - _wsz))                     \
            return 0;                                                        \
        if ((ctx)->offset <= (MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)) {      \
            if (bpf_probe_read(                                              \
                &((ctx)->sbt->buf[(ctx)->offset]),                           \
                _wsz,                                                        \
                (src_ptr)) == 0) {                                           \
                (ctx)->offset += _wsz;                                       \
            }                                                                \
        }                                                                    \
    } while (0)

/*
 * EVT_WRITE — explicit single-field writer (kept for cases where size must be
 * supplied explicitly, e.g. struct hds_socket_info).
 *   EVT_WRITE(ctx, ptr)        → length-prefixed string
 *   EVT_WRITE(ctx, ptr, size)  → raw bytes
 */
#define _EVT_WRITE_SELECT(_c, _p, _s, _NAME, ...) _NAME
#define EVT_WRITE(ctx, ptr, ...)                                             \
    _EVT_WRITE_SELECT(ctx, ptr, ##__VA_ARGS__,                               \
        _EVT_WRITE_BYTES, _EVT_WRITE_STR)(ctx, ptr, ##__VA_ARGS__)

/* Socket serializer wrapper for EVT_SUBMIT argument list. */
struct evt_proc_sock_ref {
    struct proc_info *proc;
};

#define EVT_SOCK(proc_ptr)                                                    \
    (&(struct evt_proc_sock_ref){                                             \
        .proc = (proc_ptr),                                                   \
    })

/*
 * EVT_WRITE_AUTO — type-inferred writer using C11 _Generic.
 *
 * Dispatches on the pointer's pointee type at compile time:
 *   u8/u16/u32/u64/s8/s16/s32/s64 pointer → raw bytes (native-endian)
 *   anything else (void*, char*, char(*)[N]) → length-prefixed string
 *
 * Both paths are syntactically valid for any pointer (bpf_probe_read* accept
 * void*), so the non-selected _Generic arm is dead-code-eliminated before the
 * BPF verifier sees it.  No runtime branch is produced.
 */
#define EVT_WRITE_AUTO(ctx, ptr)                                             \
    _Generic((ptr),                                                          \
        u8  *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(u8));  }),               \
        u16 *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(u16)); }),               \
        u32 *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(u32)); }),               \
        u64 *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(u64)); }),               \
        s8  *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(s8));  }),               \
        s16 *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(s16)); }),               \
        s32 *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(s32)); }),               \
        s64 *: ({ _EVT_WRITE_BYTES(ctx, ptr, sizeof(s64)); }),               \
        struct hds_socket_info   *: ({                                       \
            _EVT_WRITE_BYTES(ctx, ptr, sizeof(struct hds_socket_info));      \
        }),                                                                  \
        struct hds_socket_info_v6*: ({                                       \
            _EVT_WRITE_BYTES(ctx, ptr, sizeof(struct hds_socket_info_v6));   \
        }),                                                                  \
        struct evt_proc_sock_ref *: ({                                       \
            struct evt_proc_sock_ref *__sr =                                 \
                (struct evt_proc_sock_ref *)(void *)(ptr);                   \
            struct proc_info *__p = __sr->proc;                              \
            if (__p) {                                                       \
                _EVT_WRITE_BYTES(ctx, &__p->family, sizeof(__u16));          \
                if (__p->family == AF_INET6)                                 \
                    _EVT_WRITE_BYTES(ctx, &__p->sinfo_v6, sizeof(struct hds_socket_info_v6)); \
                else if (__p->family == AF_INET)                             \
                    _EVT_WRITE_BYTES(ctx, &__p->sinfo, sizeof(struct hds_socket_info)); \
            }                                                                \
        }),                                                                  \
        default: ({ _EVT_WRITE_STR(ctx, ptr); }))

/*
 * Variadic arg counter — supports up to 48 args (48 auto-typed fields).
 * Prepend N user tokens before the descending sequence 48..0; the value at
 * fixed position 49 always equals N.
 */
#define _EVT_N_ARGS(...)   _EVT_ARGS_C(__VA_ARGS__, _EVT_ARGS_S())
#define _EVT_ARGS_C(...)   _EVT_ARGS_N(__VA_ARGS__)
#define _EVT_ARGS_N(                                                         \
     _1, _2, _3, _4, _5, _6, _7, _8, _9,_10,_11,_12,                       \
    _13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,                        \
    _25,_26,_27,_28,_29,_30,_31,_32,_33,_34,_35,_36,                        \
    _37,_38,_39,_40,_41,_42,_43,_44,_45,_46,_47,_48,                        \
    N, ...) N
#define _EVT_ARGS_S()                                                        \
    48,47,46,45,44,43,42,41,40,39,38,37,                                     \
    36,35,34,33,32,31,30,29,28,27,26,25,                                     \
    24,23,22,21,20,19,18,17,16,15,14,13,                                     \
    12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

/*
 * Single-item iteration chain.  Each slot calls EVT_WRITE_AUTO for one field
 * then delegates the remaining args to the next-smaller macro.
 */
#define _EVT_ITEMS_1(ctx, P)        EVT_WRITE_AUTO(ctx, P)
#define _EVT_ITEMS_2(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_1(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_3(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_2(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_4(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_3(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_5(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_4(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_6(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_5(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_7(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_6(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_8(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_7(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_9(ctx, P, ...)   EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_8(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_10(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_9(ctx,  __VA_ARGS__)
#define _EVT_ITEMS_11(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_10(ctx, __VA_ARGS__)
#define _EVT_ITEMS_12(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_11(ctx, __VA_ARGS__)
#define _EVT_ITEMS_13(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_12(ctx, __VA_ARGS__)
#define _EVT_ITEMS_14(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_13(ctx, __VA_ARGS__)
#define _EVT_ITEMS_15(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_14(ctx, __VA_ARGS__)
#define _EVT_ITEMS_16(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_15(ctx, __VA_ARGS__)
#define _EVT_ITEMS_17(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_16(ctx, __VA_ARGS__)
#define _EVT_ITEMS_18(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_17(ctx, __VA_ARGS__)
#define _EVT_ITEMS_19(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_18(ctx, __VA_ARGS__)
#define _EVT_ITEMS_20(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_19(ctx, __VA_ARGS__)
#define _EVT_ITEMS_21(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_20(ctx, __VA_ARGS__)
#define _EVT_ITEMS_22(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_21(ctx, __VA_ARGS__)
#define _EVT_ITEMS_23(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_22(ctx, __VA_ARGS__)
#define _EVT_ITEMS_24(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_23(ctx, __VA_ARGS__)
#define _EVT_ITEMS_25(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_24(ctx, __VA_ARGS__)
#define _EVT_ITEMS_26(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_25(ctx, __VA_ARGS__)
#define _EVT_ITEMS_27(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_26(ctx, __VA_ARGS__)
#define _EVT_ITEMS_28(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_27(ctx, __VA_ARGS__)
#define _EVT_ITEMS_29(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_28(ctx, __VA_ARGS__)
#define _EVT_ITEMS_30(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_29(ctx, __VA_ARGS__)
#define _EVT_ITEMS_31(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_30(ctx, __VA_ARGS__)
#define _EVT_ITEMS_32(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_31(ctx, __VA_ARGS__)
#define _EVT_ITEMS_33(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_32(ctx, __VA_ARGS__)
#define _EVT_ITEMS_34(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_33(ctx, __VA_ARGS__)
#define _EVT_ITEMS_35(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_34(ctx, __VA_ARGS__)
#define _EVT_ITEMS_36(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_35(ctx, __VA_ARGS__)
#define _EVT_ITEMS_37(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_36(ctx, __VA_ARGS__)
#define _EVT_ITEMS_38(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_37(ctx, __VA_ARGS__)
#define _EVT_ITEMS_39(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_38(ctx, __VA_ARGS__)
#define _EVT_ITEMS_40(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_39(ctx, __VA_ARGS__)
#define _EVT_ITEMS_41(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_40(ctx, __VA_ARGS__)
#define _EVT_ITEMS_42(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_41(ctx, __VA_ARGS__)
#define _EVT_ITEMS_43(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_42(ctx, __VA_ARGS__)
#define _EVT_ITEMS_44(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_43(ctx, __VA_ARGS__)
#define _EVT_ITEMS_45(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_44(ctx, __VA_ARGS__)
#define _EVT_ITEMS_46(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_45(ctx, __VA_ARGS__)
#define _EVT_ITEMS_47(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_46(ctx, __VA_ARGS__)
#define _EVT_ITEMS_48(ctx, P, ...)  EVT_WRITE_AUTO(ctx, P); _EVT_ITEMS_47(ctx, __VA_ARGS__)

/* EVT_SUBMIT(ctx, ptr, ptr, ...) — batch auto-typed writer.
 * Arg count resolved at compile time; each pointer dispatched by EVT_WRITE_AUTO. */
#define _EVT_SUBMIT_CALL(ctx, n, ...) _EVT_ITEMS_##n(ctx, __VA_ARGS__)
#define _EVT_SUBMIT_N(ctx, n, ...)    _EVT_SUBMIT_CALL(ctx, n, __VA_ARGS__)
#define EVT_SUBMIT(ctx, ...)          _EVT_SUBMIT_N(ctx, _EVT_N_ARGS(__VA_ARGS__), __VA_ARGS__)

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