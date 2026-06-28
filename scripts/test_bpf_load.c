#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object>\n", argv[0]);
        return 1;
    }
    
    libbpf_set_print(libbpf_print_fn);
    
    struct bpf_object *obj = bpf_object__open(argv[1]);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "bpf_object__load failed: %d (%s)\n", err, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    printf("BPF object loaded successfully\n");
    bpf_object__close(obj);
    return 0;
}
