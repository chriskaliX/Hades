CMD_CLANG ?= clang

LIB_PATH := ../libs
LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDLAGS =
LIBBPF_SRC = $(LIB_PATH)/libbpf/src

headers/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \

	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		DESTDIR=$(abspath ./src/bpf/headers/libbpf/) \
		OBJDIR=$(abspath ./src/bpf/headers/libbpf/obj) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
		install install_uapi_headers
	install -m 0640 ./src/bpf/headers/libbpf/bpf/*.h ./src/bpf/headers/

build: \
	headers/libbpf/libbpf.a

	cargo fmt
	RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib/x86_64-linux-gnu/" cargo build --release --target x86_64-unknown-linux-gnu --features=static

debug: \
	headers/libbpf/libbpf.a

	cargo fmt
	RUST_BACKTRACE=1 RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib/x86_64-linux-gnu/" cargo build --release --target x86_64-unknown-linux-gnu --features=static,debug

test:
	cargo fmt
	RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib/x86_64-linux-gnu/" cargo test --target x86_64-unknown-linux-gnu --features=debug,static