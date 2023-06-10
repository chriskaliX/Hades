# Eguard

> **Warning**
> This plugin is experimental and still under developing

> eguard is meant for the formal version of edr. This is based on libbpf-rs and will add BTFhub into this project.

## Quick start

> prerequisite: BTF supported kernel version (will move on to the BTFHub in the feature)

> install the tools. `cargo install libbpf-cargo`

1. `cargo libbpf make`
2. `./target/debug/eguard`

## QA

1. Why Rust

    Nothing special. This would be easier if we use golang since edriver is already finished. Just want to try things differently, which means we may trans to golang if the libs of rust is not as good as we want.

2. What the features?

    Several basic features which, I think, would be useful in real world. Detection is NOT the purpose of this plugin.

    1. TC-based ip restriction
    2. Dns-based restriction
    3. File access restriction
    4. Kernel exploit detection

    For now, I am working on feature 1.