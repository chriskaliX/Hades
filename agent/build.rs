fn main() {
    // ── Inject build-time configuration from [package.metadata.hades] ──────
    // Values can be overridden by environment variables of the same name.
    // build.rs emits them as cargo:rustc-env so they are available via env!()
    // in the source code.
    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml")
    ).expect("parse Cargo.toml");
    let meta = &manifest["package"]["metadata"]["hades"];

    let grpc_addr = std::env::var("GRPC_ADDR")
        .unwrap_or_else(|_| meta["grpc_addr"].as_str().unwrap().to_owned());
    println!("cargo:rustc-env=GRPC_ADDR={grpc_addr}");
    println!("cargo:rerun-if-env-changed=GRPC_ADDR");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // ── Compile gRPC proto definitions (client side only) ───────────────────
    tonic_prost_build::configure()
        .build_server(false)
        .out_dir("src/proto")
        .type_attribute(".", "#[allow(clippy::all)]")
        .type_attribute("grpc.EncodedRecord", "#[allow(dead_code)]")
        .compile_protos(
            &["proto/grpc.proto"],
            &["proto"],
        )
        .expect("failed to compile proto files");
}
