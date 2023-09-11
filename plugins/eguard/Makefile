all:
	cargo fmt
	RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib/x86_64-linux-gnu/" cargo build --release --target x86_64-unknown-linux-gnu --features=static

test:
	cargo fmt
	RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib/x86_64-linux-gnu/" cargo test --target x86_64-unknown-linux-gnu --features=debug,static  -- --nocapture