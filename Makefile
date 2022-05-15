CLANG ?= clang
STRIP ?= llvm-strip

TARGET_X86 := __TARGET_ARCH_x86
TARGET_ARM64 := __TARGET_ARCH_arm64
LDFLAGS_X86 := "-extldflags '-static -L/usr/x86_64-linux-musl/lib64'"
LDFLAGS_ARM64 := "-extldflags '-static -L/usr/aarch64-linux-musl/lib64/'"
CFLAGS := -c -O2 -g -Wall -D $(TARGET_ARM64) -target bpf -I $(shell pwd)/include $(CFLAGS)
GO_LDFLAGS := -ldflags=$(LDFLAGS_ARM64)

all: wiretap compile_commands.json

builddepends:
	sudo apt install golang clang-13 libbpf-dev bear

include:
	mkdir -p include

include/vmlinux.h: include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: include/vmlinux.h
	go generate ./...

wiretap: generate
	go build $(GO_LDFLAGS) -o wiretap cmd/wiretap/main.go

compile_commands.json:
	bear -- $(CLANG) $(CFLAGS) pkg/probe/*/bpf/*.bpf.c

clean:
	rm  wiretap \
		compile_commands.json \
		include/vmlinux.h \
		pkg/probe/*/*.o \
		pkg/probe/*/*_bpfe*.go
