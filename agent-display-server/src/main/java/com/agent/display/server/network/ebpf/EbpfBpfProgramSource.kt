package com.agent.display.server.network.ebpf

/**
 * eBPF 内核探测程序 (C 源码模板与元数据定义)。
 *
 * 挂载点说明：
 * - uprobe/SSL_write: 在进入 Conscrypt/BoringSSL 的 SSL_write(ssl, buf, num) 时捕获待发送的明文数据 (HTTP Request)
 * - uretprobe/SSL_read: 在 Conscrypt/BoringSSL 的 SSL_read(ssl, buf, num) 返回时捕获接收到的明文数据 (HTTP Response)
 *
 * 内核态过滤：
 * - 声明 BPF_MAP_TYPE_ARRAY 类型的 target_uid_map；
 * - 每次 uprobe 触发时调用 bpf_get_current_uid_gid() 获取当前进程 UID；
 * - 若非目标 UID，立刻返回 0，零开销、零干扰。
 */
object EbpfBpfProgramSource {

    const val EBPF_C_SOURCE: String = """
// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * AAU (Android Agent Use) Root-Mode eBPF TLS Plaintext Capture Probe
 * Targets BoringSSL / Conscrypt on Android 12+ GKI (Kernel 5.4+)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUFFER_CHUNK 4096

// 事件方向
#define DIRECTION_OUTBOUND_WRITE 1 // SSL_write (Request)
#define DIRECTION_INBOUND_READ   2 // SSL_read  (Response)

// 传递给用户态环形缓冲区的明文事件载荷
struct tls_event {
    u32 pid;
    u32 uid;
    u64 timestamp_ns;
    u64 ssl_ptr;
    u32 direction;
    u32 length;
    u8  data[MAX_BUFFER_CHUNK];
};

// 目标 UID 过滤 Map (由用户态动态写入当前被测试的目标应用 UID)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} target_uid_map SEC(".maps");

// 跟踪 SSL_read 入参缓冲区指针的哈希表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // tid
    __type(value, u64); // buf ptr
    __uint(max_entries, 1024);
} ssl_read_args SEC(".maps");

// 事件环形缓冲区 (Ring Buffer，Linux 5.8+ 原生高效队列)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB Ring Buffer
} tls_events SEC(".maps");

// 快速校验当前进程是否属于 targetUid，非目标进程直接放行绕过
static __always_inline bool check_target_uid(void) {
    u32 zero = 0;
    u32 *expected_uid = bpf_map_lookup_elem(&target_uid_map, &zero);
    if (!expected_uid || *expected_uid == 0) {
        return false;
    }
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 current_uid = (u32)(uid_gid & 0xFFFFFFFF);
    return (current_uid == *expected_uid);
}

// ==========================================
// 1. SSL_write 入口挂载点 (捕获明文请求)
// int SSL_write(SSL *ssl, const void *buf, int num);
// ==========================================
SEC("uprobe/SSL_write")
int probe_ssl_write_entry(struct pt_regs *ctx) {
    if (!check_target_uid()) {
        return 0; // 非目标应用完全不挂载、不干扰
    }

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0 || !buf) {
        return 0;
    }

    struct tls_event *event = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (!event) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event->pid = (u32)(pid_tgid >> 32);
    event->uid = (u32)(uid_gid & 0xFFFFFFFF);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_ptr = (u64)ssl;
    event->direction = DIRECTION_OUTBOUND_WRITE;

    u32 copy_len = (num < MAX_BUFFER_CHUNK) ? (u32)num : MAX_BUFFER_CHUNK;
    event->length = copy_len;
    bpf_probe_read_user(event->data, copy_len, buf);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ==========================================
// 2. SSL_read 入口挂载点 (保存目标缓冲区指针)
// int SSL_read(SSL *ssl, void *buf, int num);
// ==========================================
SEC("uprobe/SSL_read")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    if (!check_target_uid()) {
        return 0;
    }

    u64 tid = bpf_get_current_pid_tgid();
    void *buf = (void *)PT_REGS_PARM2(ctx);
    if (buf) {
        u64 buf_addr = (u64)buf;
        bpf_map_update_elem(&ssl_read_args, &tid, &buf_addr, BPF_ANY);
    }
    return 0;
}

// ==========================================
// 3. SSL_read 返回挂载点 (捕获明文响应)
// int SSL_read(SSL *ssl, void *buf, int num);
// ==========================================
SEC("uretprobe/SSL_read")
int probe_ssl_read_ret(struct pt_regs *ctx) {
    if (!check_target_uid()) {
        return 0;
    }

    u64 tid = bpf_get_current_pid_tgid();
    u64 *buf_ptr = bpf_map_lookup_elem(&ssl_read_args, &tid);
    if (!buf_ptr) {
        return 0;
    }

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_read_args, &tid);
        return 0;
    }

    struct tls_event *event = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (!event) {
        bpf_map_delete_elem(&ssl_read_args, &tid);
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event->pid = (u32)(pid_tgid >> 32);
    event->uid = (u32)(uid_gid & 0xFFFFFFFF);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_ptr = 0; // uretprobe 不一定直接持有 ssl 寄存器，由流会话按 tid/pid 归集
    event->direction = DIRECTION_INBOUND_READ;

    u32 copy_len = (ret < MAX_BUFFER_CHUNK) ? (u32)ret : MAX_BUFFER_CHUNK;
    event->length = copy_len;
    bpf_probe_read_user(event->data, copy_len, (void *)(*buf_ptr));

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&ssl_read_args, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
"""
}
