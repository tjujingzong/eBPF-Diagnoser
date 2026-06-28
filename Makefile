ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG   ?= clang
CC      ?= gcc

BPF_SRC  = $(wildcard bpf/*.bpf.c)
BPF_OBJ  = $(patsubst bpf/%.bpf.c,build/bpf/%.bpf.o,$(BPF_SRC))
LOADER_SRC = bpf/loader/bpf_loader.c
LOADER   = build/bin/bpf_loader

CFLAGS_BPF = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I bpf/common
CFLAGS_LOADER = -Wall -O2 -g $(shell pkg-config --cflags libbpf 2>/dev/null)
LDFLAGS_LOADER = $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf") -lelf -lz

.PHONY: all clean bpf loader install pip-install dev

all: bpf loader

bpf: $(BPF_OBJ)

build/bpf/%.bpf.o: bpf/%.bpf.c bpf/common/*.h
	@mkdir -p build/bpf
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

loader: $(LOADER)

$(LOADER): $(LOADER_SRC)
	@mkdir -p build/bin
	$(CC) $(CFLAGS_LOADER) -o $@ $< $(LDFLAGS_LOADER)

# 编译BPF程序 + loader，然后通过pip安装Python包
install: all pip-install

# 通过pip安装Python CLI工具
pip-install:
	pip install -e .

# 开发模式安装 (包含开发依赖)
dev: all
	pip install -e ".[dev]"

# 传统安装: 复制二进制到系统目录
install-bin: all
	install -d $(DESTDIR)/opt/ebpf-diagnoser/bpf
	install -d $(DESTDIR)/opt/ebpf-diagnoser/bin
	install -m 644 $(BPF_OBJ) $(DESTDIR)/opt/ebpf-diagnoser/bpf/
	install -m 755 $(LOADER) $(DESTDIR)/opt/ebpf-diagnoser/bin/

clean:
	rm -rf build/
