CLANG ?= clang
STRIP ?= llvm-strip

LDFLAGS := "-extldflags '-static -L/usr/x86_64-linux-musl/lib64'"
CFLAGS := -c -O2 -g -Wall -D __TARGET_ARCH_x86 -target bpf -I $(shell pwd)/include $(CFLAGS)
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
		compile_commands.json \
		include/vmlinux.h \
		pkg/probe/*/*.o \
		pkg/probe/*/*_bpfe*.go
