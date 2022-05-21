CLANG ?= clang
STRIP ?= llvm-strip

TARGET_X86_64 := __TARGET_ARCH_x86
TARGET_ARM64 := __TARGET_ARCH_arm64
LDFLAGS_X86_64 := "-extldflags '-static -L/usr/x86_64-linux-musl/lib64'"
LDFLAGS_ARM64 := "-extldflags '-static -L/usr/aarch64-linux-musl/lib64'"

UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH), aarch64)
	TARGET := $(TARGET_ARM64)
	LDFLAGS := $(LDFLAGS_ARM64)
else ifeq ($(UNAME_ARCH), x86_64)
	TARGET := $(TARGET_X86_64)
	LDFLAGS := $(LDFLAGS_X86_64)
else
	$(error Unsupported architecture: $(UNAME_ARCH))
endif

CFLAGS := -c -O2 -g -Wall -D $(TARGET) -target bpf -I $(shell pwd)/include $(CFLAGS)
GO_LDFLAGS := -ldflags=$(LDFLAGS)

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
		*.o \
		compile_commands.json \
		include/vmlinux.h \
		pkg/probe/*/*.o \
		pkg/probe/*/*_bpfe*.go
