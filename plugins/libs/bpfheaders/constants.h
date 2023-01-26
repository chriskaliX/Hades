#ifndef __CONSTANTS_H
#define __CONSTANTS_H
    // LOAD_CONSTANT by golang runtime. REPLACE some trival eBPF maps.
    #define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))
    // constants defination
    static __always_inline u64 hades_constants_pgid()
    {
        u64 val = 0;
        LOAD_CONSTANT("hades_pgid", val);
        return val;
    }

    static __always_inline __u64 hades_constants_stext() {
        __u64 val = 0;
        LOAD_CONSTANT("hades_stext", val);
        return val;
    }

    static __always_inline __u64 hades_constants_etext() {
        __u64 val = 0;
        LOAD_CONSTANT("hades_etext", val);
        return val;
    }
#endif
