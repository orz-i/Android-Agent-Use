// SPDX-License-Identifier: GPL-2.0
// Minimal CO-RE-free eBPF probe for Android Conscrypt/BoringSSL SSL_write & SSL_read.
// Compiles cleanly with Android NDK clang --target=bpf with zero external kernel headers.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;

#define SEC(NAME) __attribute__((section(NAME), used))

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

#define BPF_ANY 0
#define BPF_F_CURRENT_CPU 0xffffffffULL

#define DIRECTION_OUTBOUND_WRITE 1U
#define DIRECTION_INBOUND_READ 2U
#define MAX_DATA_CHUNK 16383U

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;

#if defined(__TARGET_ARCH_arm64)
struct pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_RC(x)    ((x)->regs[0])
#elif defined(__TARGET_ARCH_x86_64)
struct pt_regs {
    __u64 r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss;
};
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_RC(x)    ((x)->rax)
#elif defined(__TARGET_ARCH_arm)
struct pt_regs {
    __u32 uregs[18];
};
#define PT_REGS_PARM1(x) ((__u64)(x)->uregs[0])
#define PT_REGS_PARM2(x) ((__u64)(x)->uregs[1])
#define PT_REGS_PARM3(x) ((__u64)(x)->uregs[2])
#define PT_REGS_RC(x)    ((__u64)(x)->uregs[0])
#elif defined(__TARGET_ARCH_x86)
struct pt_regs {
    __u32 bx, cx, dx, si, di, bp, ax, ds, es, fs, gs, orig_ax, ip, cs, flags, sp, ss;
};
static __inline __u64 bpf_read_x86_stack_arg(struct pt_regs *ctx, __u32 slot) {
    __u32 val = 0;
    bpf_probe_read_user(&val, sizeof(val), (const void *)(unsigned long)(ctx->sp + 4U * slot));
    return (__u64)val;
}
#define PT_REGS_PARM1(x) bpf_read_x86_stack_arg((x), 1)
#define PT_REGS_PARM2(x) bpf_read_x86_stack_arg((x), 2)
#define PT_REGS_PARM3(x) bpf_read_x86_stack_arg((x), 3)
#define PT_REGS_RC(x)    ((__u64)(x)->ax)
#else
#error "Unsupported __TARGET_ARCH_* for aau_ebpf.bpf.c"
#endif

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct tls_event_hdr {
    __u32 pid;
    __u32 uid;
    __u64 ssl_ptr;
    __u32 direction;
    __u32 length;
};

struct tls_event {
    struct tls_event_hdr hdr;
    __u8 data[MAX_DATA_CHUNK + 1];
};

struct ssl_read_args_val {
    __u64 ssl_ptr;
    __u64 buf_ptr;
};

SEC("maps")
struct bpf_map_def target_uid_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
    .map_flags = 0,
};

SEC("maps")
struct bpf_map_def ssl_read_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct ssl_read_args_val),
    .max_entries = 4096,
    .map_flags = 0,
};

SEC("maps")
struct bpf_map_def event_scratch = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct tls_event),
    .max_entries = 1,
    .map_flags = 0,
};

// max_entries == 0 tells loader to allocate num_cpus slots
SEC("maps")
struct bpf_map_def events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 0,
    .map_flags = 0,
};

static __inline __u32 match_target_uid(void) {
    __u32 zero = 0;
    __u32 *expected_uid = bpf_map_lookup_elem(&target_uid_map, &zero);
    if (!expected_uid || *expected_uid == 0) {
        return 0;
    }
    __u32 current_uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFFULL);
    if (current_uid != *expected_uid) {
        return 0;
    }
    return current_uid;
}

static __inline void emit_ssl_chunk(
    struct pt_regs *ctx,
    __u32 uid,
    __u64 ssl_ptr,
    const void *buf_ptr,
    __s32 len,
    __u32 direction
) {
    if (len <= 0 || !buf_ptr) {
        return;
    }

    __u32 copy_len = (__u32)len;
    if (copy_len > MAX_DATA_CHUNK) {
        copy_len = MAX_DATA_CHUNK;
    }
    copy_len &= MAX_DATA_CHUNK;
    if (copy_len == 0) {
        return;
    }

    __u32 zero = 0;
    struct tls_event *ev = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!ev) {
        return;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->hdr.pid = (__u32)(pid_tgid >> 32);
    ev->hdr.uid = uid;
    ev->hdr.ssl_ptr = ssl_ptr;
    ev->hdr.direction = direction;
    ev->hdr.length = copy_len;

    if (bpf_probe_read_user(ev->data, copy_len, buf_ptr) != 0) {
        return;
    }

    __u32 emit_size = (__u32)sizeof(struct tls_event_hdr) + copy_len;
    emit_size &= 0x7FFFU;
    if (emit_size <= sizeof(struct tls_event_hdr) || emit_size > sizeof(struct tls_event)) {
        return;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, emit_size);
}

SEC("uprobe/ssl_write")
int probe_ssl_write_entry(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)(unsigned long)PT_REGS_PARM2(ctx);
    __s32 num = (__s32)PT_REGS_PARM3(ctx);

    emit_ssl_chunk(ctx, uid, ssl, buf, num, DIRECTION_OUTBOUND_WRITE);
    return 0;
}

SEC("uprobe/ssl_read_enter")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_args_val args = {
        .ssl_ptr = (__u64)PT_REGS_PARM1(ctx),
        .buf_ptr = (__u64)PT_REGS_PARM2(ctx),
    };
    if (args.buf_ptr == 0) {
        return 0;
    }
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/ssl_read_exit")
int probe_ssl_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_args_val *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    __u64 ssl = args->ssl_ptr;
    const void *buf = (const void *)(unsigned long)args->buf_ptr;
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);

    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __s32 ret = (__s32)PT_REGS_RC(ctx);
    emit_ssl_chunk(ctx, uid, ssl, buf, ret, DIRECTION_INBOUND_READ);
    return 0;
}

char _license[] SEC("license") = "GPL";
