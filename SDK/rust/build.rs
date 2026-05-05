fn main() {
    prost_build::Config::new()
        .out_dir("src")
        .compile_protos(&["../transfer.proto"], &["../"])
        .expect("proto compile failed");
}
