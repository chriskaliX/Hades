TARGET     ?= x86_64-unknown-linux-musl
OUTPUT_DIR ?= .
BINARY     := collector

# CC for musl C deps (ring etc.). Do NOT set CARGO_TARGET_xxx_LINKER here.
export CC_x86_64_unknown_linux_musl ?= musl-gcc

.PHONY: all release debug clean

all: release

release:
	cargo build --release --target $(TARGET)
	cp target/$(TARGET)/release/$(BINARY) $(OUTPUT_DIR)/$(BINARY)

debug:
	cargo build --features debug --target $(TARGET)
	cp target/$(TARGET)/debug/$(BINARY) $(OUTPUT_DIR)/$(BINARY)

clean:
	cargo clean
