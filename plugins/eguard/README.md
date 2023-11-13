# Eguard

> **Warning**
> This plugin is experimental and still under developing

> eguard is meant for the formal version of edr. This is based on libbpf-rs and will add BTFhub into this project.

## Features

- [x] (Layer 4) TC-based ip restriction
- [x] (Layer 7) Dns-based restriction
- [ ] File access restriction
- [ ] Kernel exploit detection

## Quick start

> prerequisite: BTF supported kernel version (will move on to the BTFHub in the feature)

> install the tools. `cargo install libbpf-cargo`

1. `cargo libbpf make`
2. `./target/debug/eguard`

For debugging usage, `make debug`

## QA

1. Why Rust

    Nothing special. This would be easier if we use golang since edriver is already finished. Just want to try things differently, which means we may trans to golang if the libs of rust is not as good as we expected.
