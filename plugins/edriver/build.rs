use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const SRC: &str = "src/bpf/hades.bpf.c";

fn main() {
    // On Ubuntu 24.04+, system libelf.a is compiled with USE_ZSTD, so linking
    // it pulls in libzstd.a.  The Ubuntu-packaged libzstd.a (1.5.5) is compiled
    // with glibc's _FORTIFY_SOURCE=2, which emits __fprintf_chk / __snprintf_chk
    // / __vsnprintf_chk references in the dictionary-training objects
    // (cover.o, fastcover.o, zdict.o).  musl libc does not provide these glibc
    // internal symbols.  We compile thin C stubs so the musl link always
    // succeeds, whether or not those symbols are reachable after --gc-sections.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let stub_src = format!("{out_dir}/glibc_fortify_stubs.c");
        std::fs::write(
            &stub_src,
            r#"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

int __fprintf_chk(FILE *stream, int flag, const char *fmt, ...) {
    (void)flag;
    va_list ap;
    va_start(ap, fmt);
    int r = vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

int __snprintf_chk(char *s, size_t n, int flag, size_t slen,
                   const char *fmt, ...) {
    (void)flag; (void)slen;
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(s, n, fmt, ap);
    va_end(ap);
    return r;
}

int __vsnprintf_chk(char *s, size_t n, int flag, size_t slen,
                    const char *fmt, va_list ap) {
    (void)flag; (void)slen;
    return vsnprintf(s, n, fmt, ap);
}
"#,
        )
        .unwrap();
        // cc::Build::compile() automatically emits:
        //   cargo:rustc-link-lib=static=glibc_fortify_stubs
        //   cargo:rustc-link-search=native=$OUT_DIR
        cc::Build::new().file(&stub_src).compile("glibc_fortify_stubs");
    }

    let out = Path::new("./src/bpf/hades.skel.rs");

    // libbpf-cargo 0.24.6+ auto-injects -D__TARGET_ARCH_<arch> when no
    // __TARGET_ARCH_ define is found in clang_args.  Do NOT pass the old
    // hard-coded -D__aarch64__ which was wrong for x86_64 builds.
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            "-D__BPF_TRACING__",
            "-DCORE",
            "-Isrc/bpf/headers/",
            "-I../libs/core/",
            "-I../libs/bpfheaders/",
            "-Isrc/bpf/",
            "-mcpu=v2",
        ])
        .build_and_generate(&out)
        .unwrap();
}
