use libbpf_cargo::SkeletonBuilder;
// use std::env;
// use std::path::PathBuf;
use std::path::Path;

const SRC: &str = "src/bpf/eguard.bpf.c";

fn main() {
    let out = Path::new("./src/bpf/eguard.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .debug(true)
        .clang_args(
            "-c -g -O2 
            -I src/bpf/headers/ 
            -I../libs/core/
            -I../libs/bpfheaders/
            -I src/bpf/ 
            -DCORE
            -D__BPF_TRACING__
            -march=bpf -mcpu=v2",
        )
        .build_and_generate(&out)
        .unwrap();
    // println!("cargo:rerun-if-changed={SRC}");
}

// btfhub backport will be added into this build.rs
