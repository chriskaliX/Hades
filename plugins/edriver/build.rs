use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const SRC: &str = "src/bpf/hades.bpf.c";

fn main() {
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
