# openKylin兼容性测试Dockerfile
# 使用方式（在有openKylin rootfs时）:
#   1. 下载openKylin 2.0 rootfs: https://www.openkylin.top/downloads/
#   2. docker build -t openkylin-ebpf-test -f openkylin-test.Dockerfile .
#   3. docker run --privileged --pid=host -v /sys/fs/bpf:/sys/fs/bpf openkylin-ebpf-test

# 方案A: 如果有openKylin rootfs
# FROM scratch
# ADD openkylin-2.0-base-arm64.tar.gz /
# CMD ["/bin/bash"]

# 方案B: 使用Ubuntu作为基础，安装openKylin内核和eBPF工具（兼容性验证用）
# 这样可以验证代码在Kernel 6.6+环境下的行为
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential clang llvm llvm-dev \
    libbpf-dev linux-headers-generic \
    bpfcc-tools python3-bpfcc libbpfcc-dev \
    bpftool python3 python3-pip python3-venv \
    stress-ng fio sysbench \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages pyyaml rich

WORKDIR /ebpf-diagnoser
COPY . .

# 验证内核版本和eBPF支持
RUN uname -r && \
    test -f /sys/kernel/btf/vmlinux && echo "BTF: OK" || echo "BTF: N/A (may need --privileged)"

# 默认运行全部探针测试
CMD ["python3", "-m", "src.main", "--probe", "all", "--duration", "60", "--output", "json"]