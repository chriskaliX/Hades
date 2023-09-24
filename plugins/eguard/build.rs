use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/eguard.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("eguard.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .debug(true)
        .clang_args(
            "-c -g -O2 
            -I src/bpf/headers/ 
            -I../libs/core/
            -I../libs/bpfheaders/
            -I src/bpf/ -DCORE",
        )
        .build_and_generate(&out)
        .unwrap();
    // println!("cargo:rerun-if-changed={SRC}");
}

// btfhub backport will be added into this build.rs
