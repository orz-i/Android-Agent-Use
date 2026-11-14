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
#define DIRECTION_SNI_HOSTNAME 3U
#define DIRECTION_CRONET_REQ 4U
#define DIRECTION_CRONET_RESP_HDR 5U
#define DIRECTION_CRONET_BODY 6U
#define DIRECTION_CRONET_FINISH 7U
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
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_RC(x)    ((x)->regs[0])
#elif defined(__TARGET_ARCH_x86_64)
struct pt_regs {
    __u64 r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss;
};
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_RC(x)    ((x)->rax)
#elif defined(__TARGET_ARCH_arm)
struct pt_regs {
    __u32 uregs[18];
};
#define PT_REGS_PARM1(x) ((__u64)(x)->uregs[0])
#define PT_REGS_PARM2(x) ((__u64)(x)->uregs[1])
#define PT_REGS_PARM3(x) ((__u64)(x)->uregs[2])
#define PT_REGS_PARM4(x) ((__u64)(x)->uregs[3])
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
#define PT_REGS_PARM4(x) bpf_read_x86_stack_arg((x), 4)
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
    __u64 ts_ns;
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

struct cronet_abi_config {
    __u32 raw_headers_offset;   // default 0x20
    __u32 iobuf_data_offset;    // default 0x10
    __u32 string_layout_mode;   // 0 = libc++ alt layout (byte[23] & 0x80), 1 = std LSB layout (byte[0] & 1)
    __u32 reserved;
};

SEC("maps")
struct bpf_map_def cronet_abi_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct cronet_abi_config),
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

static __inline __attribute__((always_inline)) void emit_ssl_chunk(
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

    __u32 total_len = (__u32)len;
    __u32 offset = 0;

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (offset >= total_len) {
            break;
        }

        __u32 remaining = total_len - offset;
        __u32 copy_len = (remaining > MAX_DATA_CHUNK) ? MAX_DATA_CHUNK : remaining;
        copy_len &= MAX_DATA_CHUNK;
        if (copy_len == 0) {
            break;
        }

        const void *src = (const void *)((const char *)buf_ptr + offset);
        if (bpf_probe_read_user(ev->data, copy_len, src) != 0) {
            break;
        }

        ev->hdr.length = copy_len;
        ev->hdr.ts_ns = (__u64)bpf_ktime_get_ns();

        __u32 emit_size = (__u32)sizeof(struct tls_event_hdr) + copy_len;
        emit_size &= 0x7FFFU;
        if (emit_size <= sizeof(struct tls_event_hdr) || emit_size > sizeof(struct tls_event)) {
            break;
        }
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, emit_size);
        offset += copy_len;
    }
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

SEC("uprobe/ssl_set_sni")
int probe_ssl_set_sni(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    const char *name = (const char *)(unsigned long)PT_REGS_PARM2(ctx);
    if (!ssl || !name) {
        return 0;
    }

    __u32 zero = 0;
    struct tls_event *ev = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!ev) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->hdr.pid = (__u32)(pid_tgid >> 32);
    ev->hdr.uid = uid;
    ev->hdr.ssl_ptr = ssl;
    ev->hdr.direction = DIRECTION_SNI_HOSTNAME;
    ev->hdr.ts_ns = (__u64)bpf_ktime_get_ns();

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        ((__u64 *)ev->data)[i] = 0;
    }

    if (bpf_probe_read_user(ev->data, 255, name) != 0) {
        if (bpf_probe_read_user(ev->data, 63, name) != 0) {
            return 0;
        }
    }
    ev->data[255] = '\0';
    if (ev->data[0] == '\0') {
        return 0;
    }

    ev->hdr.length = 256U;
    __u32 emit_size = (__u32)sizeof(struct tls_event_hdr) + 256U;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, emit_size);
    return 0;
}

struct libcxx_alt_string {
    __u64 first;   // alt short: chars[0..7], alt long: const char *data; std short: len<<1|0 + chars[0..6], std long: cap|1
    __u64 second;  // alt long / std long: __u64 size
    union {
        __u8 tail[8];  // tail[7] (offset 23): alt short => len, alt long => MSB cap (bit7==1)
        __u64 third;   // std long: const char *data
    };
};

static __inline __attribute__((always_inline)) __u32 read_alt_libcxx_string(
    __u8 *dst,
    __u32 max_copy,
    const void *str_ptr,
    __u32 layout_mode
) {
    if (!dst || !str_ptr || max_copy == 0) {
        return 0;
    }

    struct libcxx_alt_string s;
    __builtin_memset(&s, 0, sizeof(s));
    if (bpf_probe_read_user(&s, sizeof(s), str_ptr) != 0) {
        return 0;
    }

    const void *data_ptr = 0;
    __u64 raw_len = 0ULL;

    if (layout_mode == 1U) {
        if ((s.first & 1ULL) == 0ULL) {
            __u32 slen = (__u32)((s.first & 0xFFULL) >> 1);
            if (slen == 0U || slen > 22U) {
                return 0;
            }
            __u32 copy_len = slen;
            if (copy_len > max_copy) {
                copy_len = max_copy;
            }
            copy_len &= 0x1FU;
            if (copy_len == 0U || copy_len > 22U) {
                return 0;
            }
            if (bpf_probe_read_user(dst, copy_len, (const __u8 *)str_ptr + 1) != 0) {
                return 0;
            }
            return copy_len;
        }
        data_ptr = (const void *)(unsigned long)s.third;
        raw_len = s.second;
    } else {
        __u8 flag = s.tail[7];
        if ((flag & 0x80U) == 0U) {
            __u32 slen = (__u32)(flag & 0x7FU);
            if (slen == 0U || slen > 22U) {
                return 0;
            }
            __u32 copy_len = slen;
            if (copy_len > max_copy) {
                copy_len = max_copy;
            }
            copy_len &= 0x1FU;
            if (copy_len == 0U || copy_len > 22U) {
                return 0;
            }
            if (bpf_probe_read_user(dst, copy_len, str_ptr) != 0) {
                return 0;
            }
            return copy_len;
        }
        data_ptr = (const void *)(unsigned long)s.first;
        raw_len = s.second;
    }

    if (!data_ptr || raw_len == 0ULL || raw_len > 65536ULL) {
        return 0;
    }
    __u32 copy_len = (__u32)raw_len;
    if (copy_len > max_copy) {
        copy_len = max_copy;
    }
    copy_len &= 0xFFFU;
    if (copy_len == 0U || copy_len > 4095U) {
        return 0;
    }
    if (bpf_probe_read_user(dst, copy_len, data_ptr) != 0) {
        return 0;
    }
    return copy_len;
}

// Hook CronetURLRequest::CronetURLRequest(..., Callback* adapter [x2], const GURL& url [x3], ...)
SEC("uprobe/cronet_create")
int probe_cronet_create(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 adapter = (__u64)PT_REGS_PARM3(ctx);
    const void *gurl_ptr = (const void *)(unsigned long)PT_REGS_PARM4(ctx);
    if (!adapter || !gurl_ptr) {
        return 0;
    }

    __u32 zero = 0;
    struct cronet_abi_config *abi = bpf_map_lookup_elem(&cronet_abi_map, &zero);
    __u32 str_mode = abi ? abi->string_layout_mode : 0U;

    struct tls_event *ev = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!ev) {
        return 0;
    }

    __u32 url_len = read_alt_libcxx_string(ev->data, 2048U, gurl_ptr, str_mode);
    url_len &= 0xFFFU;
    if (url_len == 0U || url_len > 2048U) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->hdr.pid = (__u32)(pid_tgid >> 32);
    ev->hdr.uid = uid;
    ev->hdr.ssl_ptr = adapter;
    ev->hdr.direction = DIRECTION_CRONET_REQ;
    ev->hdr.length = url_len;
    ev->hdr.ts_ns = (__u64)bpf_ktime_get_ns();

    __u32 emit_size = (__u32)sizeof(struct tls_event_hdr) + url_len;
    emit_size &= 0x1FFFU;
    if (emit_size <= sizeof(struct tls_event_hdr) || emit_size > sizeof(struct tls_event)) {
        return 0;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, emit_size);
    return 0;
}

// Hook CronetURLRequestAdapter::OnResponseStarted(adapter [x0], int http_status_code [w1], ..., const net::HttpResponseHeaders* headers [x3], ...)
SEC("uprobe/cronet_resp_started")
int probe_cronet_resp_started(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 adapter = (__u64)PT_REGS_PARM1(ctx);
    __u32 status_code = (__u32)PT_REGS_PARM2(ctx);
    const char *hdrs_ptr = (const char *)(unsigned long)PT_REGS_PARM4(ctx);
    if (!adapter) {
        return 0;
    }

    __u32 zero = 0;
    struct cronet_abi_config *abi = bpf_map_lookup_elem(&cronet_abi_map, &zero);
    __u32 raw_hdr_off = 0x20U;
    if (abi && abi->raw_headers_offset > 0U && abi->raw_headers_offset <= 256U) {
        raw_hdr_off = abi->raw_headers_offset & 0xFFU;
    }
    __u32 str_mode = abi ? abi->string_layout_mode : 0U;

    struct tls_event *ev = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!ev) {
        return 0;
    }

    *(__u32 *)ev->data = status_code;
    __u32 hdr_len = 0;
    if (hdrs_ptr) {
        hdr_len = read_alt_libcxx_string(ev->data + 4, 4095U, hdrs_ptr + raw_hdr_off, str_mode);
        hdr_len &= 0xFFFU;
        if (hdr_len > 4095U) {
            hdr_len = 0U;
        }
    }

    __u32 payload_len = 4U + hdr_len;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->hdr.pid = (__u32)(pid_tgid >> 32);
    ev->hdr.uid = uid;
    ev->hdr.ssl_ptr = adapter;
    ev->hdr.direction = DIRECTION_CRONET_RESP_HDR;
    ev->hdr.length = payload_len;
    ev->hdr.ts_ns = (__u64)bpf_ktime_get_ns();

    __u32 emit_size = (__u32)sizeof(struct tls_event_hdr) + payload_len;
    emit_size &= 0x1FFFU;
    if (emit_size <= sizeof(struct tls_event_hdr) || emit_size > sizeof(struct tls_event)) {
        return 0;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, emit_size);
    return 0;
}

// Hook CronetURLRequestAdapter::OnReadCompleted(adapter [x0], net::IOBuffer* read_buffer [x1], int bytes_read [w2])
SEC("uprobe/cronet_read_completed")
int probe_cronet_read_completed(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 adapter = (__u64)PT_REGS_PARM1(ctx);
    const char *iobuf_ptr = (const char *)(unsigned long)PT_REGS_PARM2(ctx);
    __s32 bytes_read = (__s32)PT_REGS_PARM3(ctx);
    if (!adapter || !iobuf_ptr || bytes_read <= 0) {
        return 0;
    }

    __u32 zero = 0;
    struct cronet_abi_config *abi = bpf_map_lookup_elem(&cronet_abi_map, &zero);
    __u32 iobuf_off = 0x10U;
    if (abi && abi->iobuf_data_offset > 0U && abi->iobuf_data_offset <= 256U) {
        iobuf_off = abi->iobuf_data_offset & 0xFFU;
    }

    const void *data_ptr = 0;
    if (bpf_probe_read_user(&data_ptr, sizeof(data_ptr), iobuf_ptr + iobuf_off) != 0 || !data_ptr) {
        return 0;
    }

    emit_ssl_chunk(ctx, uid, adapter, data_ptr, bytes_read, DIRECTION_CRONET_BODY);
    return 0;
}

// Hook CronetURLRequestAdapter::OnSucceeded(adapter [x0], ...)
SEC("uprobe/cronet_succeeded")
int probe_cronet_succeeded(struct pt_regs *ctx) {
    __u32 uid = match_target_uid();
    if (uid == 0) {
        return 0;
    }

    __u64 adapter = (__u64)PT_REGS_PARM1(ctx);
    if (!adapter) {
        return 0;
    }

    __u32 zero = 0;
    struct tls_event *ev = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!ev) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->hdr.pid = (__u32)(pid_tgid >> 32);
    ev->hdr.uid = uid;
    ev->hdr.ssl_ptr = adapter;
    ev->hdr.direction = DIRECTION_CRONET_FINISH;
    ev->hdr.length = 4U;
    ev->hdr.ts_ns = (__u64)bpf_ktime_get_ns();
    *(__u32 *)ev->data = 0U;

    __u32 emit_size = (__u32)sizeof(struct tls_event_hdr) + 4U;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, emit_size);
    return 0;
}

char _license[] SEC("license") = "GPL";
