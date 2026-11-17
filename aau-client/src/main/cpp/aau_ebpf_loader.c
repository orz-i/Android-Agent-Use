#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "aau_ebpf_bpf_blob.h"

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif
#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif

#define MAX_DATA_CHUNK 16383U
#define MAX_ATTACHED_LIBS 16
#define MAX_LIB_DIRS 16
#define MAX_BATCH_EVENTS 512
#define MAX_OFFSET_RULES 16
#define MAX_CRONET_SIGS 8

typedef struct {
    char lib_substr[128];
    uint64_t write_off;
    uint64_t read_off;
    uint64_t sni_off;
} ssl_offset_rule;

typedef struct {
    char lib_substr[128];
    uint64_t create_off;
    uint64_t hdr_off;
    uint64_t body_off;
    uint64_t fin_off;
} cronet_offset_rule;

typedef struct {
    uint32_t raw_headers_offset;
    uint32_t iobuf_data_offset;
    uint32_t string_layout_mode;
    uint32_t reserved;
} cronet_abi_config;

static volatile sig_atomic_t g_stop = 0;
static char g_tracefs_dir[256] = {0};
static char g_probe_prefix[64] = {0};
static char g_lib_dirs[MAX_LIB_DIRS][512];
static int g_lib_dir_count = 0;
static ssl_offset_rule g_ssl_rules[MAX_OFFSET_RULES];
static int g_ssl_rule_count = 0;
static cronet_offset_rule g_cronet_rules[MAX_OFFSET_RULES];
static int g_cronet_rule_count = 0;
static char g_custom_cronet_sigs[MAX_CRONET_SIGS][128];
static int g_custom_cronet_sig_count = 0;
static int g_cronet_slot_hdr = 3;
static int g_cronet_slot_body = 4;
static int g_cronet_slot_fin = 5;
static cronet_abi_config g_cronet_abi = {0x20U, 0x10U, 0U, 0U};

typedef struct {
    char path[512];
    dev_t dev;
    ino_t ino;
    uint64_t off_write;
    uint64_t off_read;
    int uprobe_fd_count;
    int uprobe_fds[8 * 128];
} attached_lib;

static attached_lib g_attached_libs[MAX_ATTACHED_LIBS];
static int g_attached_lib_count = 0;
static char g_last_attach_err[256] = {0};

static void set_last_attach_err(const char *msg) {
    if (msg && msg[0]) {
        snprintf(g_last_attach_err, sizeof(g_last_attach_err), "%s", msg);
    }
}

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static inline int sys_perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags
) {
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static uint32_t detect_kernel_version_code(void) {
    struct utsname u;
    if (uname(&u) != 0) return 0;
    unsigned int maj = 0, min = 0, pat = 0;
    sscanf(u.release, "%u.%u.%u", &maj, &min, &pat);
    if (pat > 255) pat = 255;
    return (maj << 16) | (min << 8) | pat;
}

static const char *find_tracefs_dir(void) {
    const char *candidates[] = {"/sys/kernel/tracing", "/sys/kernel/debug/tracing", NULL};
    for (int i = 0; candidates[i]; i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s/uprobe_events", candidates[i]);
        if (access(path, F_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

static int file_exists_nonempty(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
}

static int resolve_elf_symbol_offset(const char *path, const char *sym_name, uint64_t *out_offset) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return -1;
    }

    size_t map_size = (size_t)st.st_size;
    void *base = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;

    int rc = -1;
    const unsigned char *ident = (const unsigned char *)base;
    if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
        munmap(base, map_size);
        return -1;
    }

#if defined(__LP64__)
    if (ident[EI_CLASS] == ELFCLASS64) {
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
        if (eh->e_shoff + eh->e_shnum * sizeof(Elf64_Shdr) <= map_size &&
            eh->e_phoff + eh->e_phnum * sizeof(Elf64_Phdr) <= map_size) {
            const Elf64_Shdr *shdrs = (const Elf64_Shdr *)((const uint8_t *)base + eh->e_shoff);
            const Elf64_Phdr *phdrs = (const Elf64_Phdr *)((const uint8_t *)base + eh->e_phoff);

            for (int i = 0; i < eh->e_shnum && rc != 0; i++) {
                if (shdrs[i].sh_type != SHT_DYNSYM && shdrs[i].sh_type != SHT_SYMTAB) continue;
                uint32_t str_idx = shdrs[i].sh_link;
                if (str_idx >= eh->e_shnum) continue;
                const char *strs = (const char *)base + shdrs[str_idx].sh_offset;
                size_t strs_size = shdrs[str_idx].sh_size;
                size_t count = shdrs[i].sh_size / sizeof(Elf64_Sym);
                const Elf64_Sym *syms = (const Elf64_Sym *)((const uint8_t *)base + shdrs[i].sh_offset);

                for (size_t s = 0; s < count; s++) {
                    if (syms[s].st_shndx == SHN_UNDEF || syms[s].st_value == 0) continue;
                    if (syms[s].st_name >= strs_size) continue;
                    const char *name = strs + syms[s].st_name;
                    if (strcmp(name, sym_name) != 0) continue;

                    uint64_t vaddr = syms[s].st_value;
                    for (int p = 0; p < eh->e_phnum; p++) {
                        if (phdrs[p].p_type == PT_LOAD &&
                            (phdrs[p].p_flags & PF_X) != 0 &&
                            vaddr >= phdrs[p].p_vaddr &&
                            vaddr < phdrs[p].p_vaddr + phdrs[p].p_memsz) {
                            uint64_t off = (vaddr - phdrs[p].p_vaddr) + phdrs[p].p_offset;
#if defined(__aarch64__)
                            if ((off & 3ULL) != 0) {
                                break;
                            }
#endif
                            *out_offset = off;
                            rc = 0;
                            break;
                        }
                    }
                    if (rc == 0) break;
                }
            }
        }
    }
#else
    if (ident[EI_CLASS] == ELFCLASS32) {
        const Elf32_Ehdr *eh = (const Elf32_Ehdr *)base;
        if (eh->e_shoff + eh->e_shnum * sizeof(Elf32_Shdr) <= map_size &&
            eh->e_phoff + eh->e_phnum * sizeof(Elf32_Phdr) <= map_size) {
            const Elf32_Shdr *shdrs = (const Elf32_Shdr *)((const uint8_t *)base + eh->e_shoff);
            const Elf32_Phdr *phdrs = (const Elf32_Phdr *)((const uint8_t *)base + eh->e_phoff);

            for (int i = 0; i < eh->e_shnum && rc != 0; i++) {
                if (shdrs[i].sh_type != SHT_DYNSYM && shdrs[i].sh_type != SHT_SYMTAB) continue;
                uint32_t str_idx = shdrs[i].sh_link;
                if (str_idx >= eh->e_shnum) continue;
                const char *strs = (const char *)base + shdrs[str_idx].sh_offset;
                size_t strs_size = shdrs[str_idx].sh_size;
                size_t count = shdrs[i].sh_size / sizeof(Elf32_Sym);
                const Elf32_Sym *syms = (const Elf32_Sym *)((const uint8_t *)base + shdrs[i].sh_offset);

                for (size_t s = 0; s < count; s++) {
                    if (syms[s].st_shndx == SHN_UNDEF || syms[s].st_value == 0) continue;
                    if (syms[s].st_name >= strs_size) continue;
                    const char *name = strs + syms[s].st_name;
                    if (strcmp(name, sym_name) != 0) continue;

                    // Mask Thumb bit (LSB) on 32-bit ARM before resolving file offset
                    uint64_t vaddr = ((uint64_t)syms[s].st_value) & ~1ULL;
                    for (int p = 0; p < eh->e_phnum; p++) {
                        if (phdrs[p].p_type == PT_LOAD &&
                            (phdrs[p].p_flags & PF_X) != 0 &&
                            vaddr >= phdrs[p].p_vaddr &&
                            vaddr < phdrs[p].p_vaddr + phdrs[p].p_memsz) {
                            *out_offset = (vaddr - phdrs[p].p_vaddr) + phdrs[p].p_offset;
                            rc = 0;
                            break;
                        }
                    }
                    if (rc == 0) break;
                }
            }
        }
    }
#endif

    munmap(base, map_size);
    return rc;
}

#if defined(__LP64__) && defined(__aarch64__)
static int ascii_strcasestr_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle || !needle[0]) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i]) {
            char a = p[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
            if (a != b) break;
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static int path_looks_like_ssl_or_cronet(const char *path) {
    return ascii_strcasestr_contains(path, "cronet") ||
           ascii_strcasestr_contains(path, "boringssl") ||
           ascii_strcasestr_contains(path, "libssl") ||
           ascii_strcasestr_contains(path, "ttnet");
}

static int elf64_vaddr_to_offset(
    const Elf64_Ehdr *eh,
    const Elf64_Phdr *phdrs,
    uint64_t vaddr,
    int require_exec,
    uint64_t *out_off
) {
    for (int p = 0; p < eh->e_phnum; p++) {
        if (phdrs[p].p_type != PT_LOAD) continue;
        if (require_exec && (phdrs[p].p_flags & PF_X) == 0) continue;
        if (vaddr >= phdrs[p].p_vaddr && vaddr < phdrs[p].p_vaddr + phdrs[p].p_filesz) {
            *out_off = (vaddr - phdrs[p].p_vaddr) + phdrs[p].p_offset;
            return 0;
        }
    }
    return -1;
}

static int elf64_offset_to_vaddr(
    const Elf64_Ehdr *eh,
    const Elf64_Phdr *phdrs,
    uint64_t off,
    uint64_t *out_vaddr
) {
    for (int p = 0; p < eh->e_phnum; p++) {
        if (phdrs[p].p_type != PT_LOAD) continue;
        if (off >= phdrs[p].p_offset && off < phdrs[p].p_offset + phdrs[p].p_filesz) {
            *out_vaddr = phdrs[p].p_vaddr + (off - phdrs[p].p_offset);
            return 0;
        }
    }
    return -1;
}

static int elf64_find_exec_range(
    const uint8_t *base,
    size_t map_size,
    const Elf64_Ehdr *eh,
    const Elf64_Phdr *phdrs,
    uint64_t *out_off,
    uint64_t *out_va,
    uint64_t *out_size
) {
    if (eh->e_shoff > 0 &&
        eh->e_shstrndx < eh->e_shnum &&
        eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) <= map_size) {
        const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(base + eh->e_shoff);
        const Elf64_Shdr *shstr_sh = &shdrs[eh->e_shstrndx];
        if (shstr_sh->sh_offset + shstr_sh->sh_size <= map_size) {
            const char *shstrs = (const char *)(base + shstr_sh->sh_offset);
            for (int i = 0; i < eh->e_shnum; i++) {
                if (shdrs[i].sh_type == SHT_PROGBITS &&
                    (shdrs[i].sh_flags & SHF_EXECINSTR) != 0 &&
                    shdrs[i].sh_name < shstr_sh->sh_size &&
                    strcmp(shstrs + shdrs[i].sh_name, ".text") == 0 &&
                    shdrs[i].sh_offset + shdrs[i].sh_size <= map_size) {
                    *out_off = shdrs[i].sh_offset;
                    *out_va = shdrs[i].sh_addr;
                    *out_size = shdrs[i].sh_size;
                    return 0;
                }
            }
        }
    }
    for (int p = 0; p < eh->e_phnum; p++) {
        if (phdrs[p].p_type == PT_LOAD &&
            (phdrs[p].p_flags & PF_X) != 0 &&
            phdrs[p].p_offset + phdrs[p].p_filesz <= map_size) {
            *out_off = phdrs[p].p_offset;
            *out_va = phdrs[p].p_vaddr;
            *out_size = phdrs[p].p_filesz;
            return 0;
        }
    }
    return -1;
}

static int64_t aarch64_bl_target_idx(const uint32_t *words, size_t idx, size_t word_count) {
    uint32_t insn = words[idx];
    if ((insn & 0xfc000000U) != 0x94000000U) return -1;
    int32_t imm26 = (int32_t)(insn & 0x03ffffffU);
    if (imm26 & 0x02000000) imm26 -= 0x04000000;
    int64_t target = (int64_t)idx + (int64_t)imm26;
    if (target < 0 || (size_t)target >= word_count) return -1;
    return target;
}

static int aarch64_is_likely_func_entry(uint32_t insn) {
    if (insn == 0xd503233fU) return 1; // PACIASP
    if (insn == 0xd503245fU) return 1; // BTI C
    if ((insn & 0xff0003ffU) == 0xd10003ffU) return 1; // SUB SP, SP, #imm
    if ((insn & 0xffe07fffU) == 0xa9807bfdU) return 1; // STP X29, X30, [SP, #-imm]!
    return 0;
}

static size_t aarch64_find_func_start(const uint32_t *words, size_t idx, size_t max_back) {
    size_t limit = (idx > max_back) ? (idx - max_back) : 0;
    for (size_t j = idx; j > limit; j--) {
        if (words[j] == 0xd503233fU) {
            return j;
        }
    }
    // Fallback for binaries built without PAC: search backwards for previous RET/BRK/tail-B boundary
    for (size_t j = idx; j > limit + 1; j--) {
        uint32_t prev = words[j - 1];
        if (prev == 0xd65f03c0U || prev == 0xd4200000U || prev == 0xd4400000U) {
            size_t k = j;
            while (k < idx && (words[k] == 0xd503201fU || words[k] == 0xd4400000U || words[k] == 0xd4200000U)) {
                k++;
            }
            if (k < idx && aarch64_is_likely_func_entry(words[k])) {
                return k;
            }
        }
    }
    return SIZE_MAX;
}

static int aarch64_window_has(const uint32_t *words, size_t start, size_t end, uint32_t opcode) {
    for (size_t k = start; k < end; k++) {
        if (words[k] == opcode) return 1;
    }
    return 0;
}

/*
 * 专门给 OpenSSL 用的入口回溯。
 *
 * 不能复用 aarch64_find_func_start：那套先找 PACIASP、再找「前一条 RET」的边界，
 * 是给 BoringSSL 写的。OpenSSL 的 SSL_write 紧跟 SSL_write_ex，前面是一条 B 跳转
 * 而不是 RET，用 RET 边界会把 SSL_write 错认成 SSL_write_ex（实测差 0x154 字节）。
 *
 * 这里直接向上扫序言，遇到 RET 才停，说明已经跨进上一个函数。
 */
static size_t openssl_scan_func_entry(const uint32_t *words, size_t idx, size_t max_back) {
    size_t limit = (idx > max_back) ? (idx - max_back) : 0;
    for (size_t j = idx; j > limit; j--) {
        uint32_t w = words[j];
        /* STP X29, X30, [SP, #-N]! */
        if ((w & 0xffc00000U) == 0xa9800000U &&
            ((w >> 5) & 31U) == 31U && (w & 31U) == 29U && ((w >> 10) & 31U) == 30U) {
            return j;
        }
        /* SUB SP, SP, #imm */
        if ((w & 0xff8003ffU) == 0xd10003ffU) return j;
        if (w == 0xd503233fU) return j;   /* PACIASP */
        if (w == 0xd65f03c0U) break;      /* RET：跨函数了 */
    }
    return SIZE_MAX;
}

static int resolve_stripped_boringssl_offsets(
    const char *path,
    uint64_t *out_write,
    uint64_t *out_read,
    uint64_t *out_sni
) {
    if (!path || !path_looks_like_ssl_or_cronet(path)) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return -1;
    }
    size_t map_size = (size_t)st.st_size;
    const uint8_t *base = (const uint8_t *)mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;

    int rc = -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
        eh->e_ident[EI_CLASS] == ELFCLASS64 &&
        eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf64_Phdr) <= map_size) {
        const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(base + eh->e_phoff);
        uint64_t text_off = 0, text_va = 0, text_sz = 0;
        if (elf64_find_exec_range(base, map_size, eh, phdrs, &text_off, &text_va, &text_sz) == 0 &&
            (text_off & 3ULL) == 0 && text_sz >= 64) {
            const uint32_t *words = (const uint32_t *)(base + text_off);
            size_t word_count = (size_t)(text_sz / 4ULL);

            // Require BoringSSL ssl_lib.cc hint when scanning generic .so filenames
            int has_ssl_lib_str = (memmem(base, map_size, "ssl/ssl_lib.cc", 14) != NULL);
            if (has_ssl_lib_str || ascii_strcasestr_contains(path, "cronet")) {
                size_t write_idx = SIZE_MAX;
                for (size_t i = 0; i < word_count; i++) {
                    if (words[i] != 0x52801c42U) continue; // MOV W2, #226
                    size_t fstart = aarch64_find_func_start(words, i, 128);
                    if (fstart == SIZE_MAX) continue;
                    size_t fend = fstart + 128;
                    if (fend > word_count) fend = word_count;
                    // Clamp to next function boundary if PACIASP is present
                    for (size_t j = fstart + 1; j < fend; j++) {
                        if (words[j] == 0xd503233fU) {
                            fend = j;
                            break;
                        }
                    }
                    if (i < fstart || i >= fend) continue;
                    if (aarch64_window_has(words, fstart, fend, 0x52800200U) && // MOV W0, #16
                        aarch64_window_has(words, fstart, fend, 0x52800842U) && // MOV W2, #66
                        aarch64_window_has(words, fstart, fend, 0x52801c42U) && // MOV W2, #226
                        aarch64_window_has(words, fstart, fend, 0x52800de2U) && // MOV W2, #111
                        aarch64_window_has(words, fstart, fend, 0x52801ae2U)) { // MOV W2, #215
                        write_idx = fstart;
                        break;
                    }
                }

                size_t read_idx = SIZE_MAX;
                if (write_idx != SIZE_MAX) {
                    size_t search_lo = (write_idx > 512) ? (write_idx - 512) : 0;
                    for (size_t i = search_lo; i < write_idx; i++) {
                        if (words[i] != 0x52800842U) continue; // MOV W2, #66 in SSL_peek
                        size_t pre = (i > 8) ? (i - 8) : 0;
                        if (!aarch64_window_has(words, pre, i, 0x52800200U)) continue;
                        size_t peek_idx = aarch64_find_func_start(words, i, 64);
                        if (peek_idx == SIZE_MAX || peek_idx == 0) continue;
                        size_t prev_idx = aarch64_find_func_start(words, peek_idx - 1, 64);
                        if (prev_idx == SIZE_MAX) continue;
                        size_t scan_hi = (prev_idx + 16 < peek_idx) ? (prev_idx + 16) : peek_idx;
                        for (size_t k = prev_idx; k < scan_hi; k++) {
                            int64_t target = aarch64_bl_target_idx(words, k, word_count);
                            if (target == (int64_t)peek_idx || target == (int64_t)(peek_idx + 1)) {
                                read_idx = prev_idx;
                                break;
                            }
                        }
                        if (read_idx != SIZE_MAX) break;
                    }
                }

                if (write_idx != SIZE_MAX && read_idx != SIZE_MAX) {
                    *out_write = text_off + (uint64_t)write_idx * 4ULL;
                    *out_read = text_off + (uint64_t)read_idx * 4ULL;
                    if (out_sni) {
                        *out_sni = 0;
                        size_t lo = (write_idx > 16384) ? (write_idx - 16384) : 0;
                        size_t hi = (write_idx + 16384 < word_count) ? (write_idx + 16384) : word_count;
                        for (size_t i = lo; i < hi; i++) {
                            if (words[i] != 0x52801aa2U) continue; // MOV W2, #213
                            size_t pre = (i > 8) ? (i - 8) : 0;
                            if (!aarch64_window_has(words, pre, i, 0x52800200U)) continue;
                            size_t sni_idx = aarch64_find_func_start(words, i, 64);
                            if (sni_idx != SIZE_MAX) {
                                *out_sni = text_off + (uint64_t)sni_idx * 4ULL;
                                break;
                            }
                        }
                    }
                    rc = 0;
                }
            }
        }
    }

    munmap((void *)base, map_size);
    return rc;
}

/* ---------- OpenSSL 1.1.x（静态链入、已 strip）偏移解析 ----------
 *
 * 很多 App 不用系统 TLS，也不用 cronet，而是把 OpenSSL 整个静态链进自己的 transport so
 * （BOSS 直聘的 libzp-sdk-transport.so 就是这一类：3.4MB，OpenSSL 1.1.1h）。
 * 这类 so 的 .dynsym 里没有任何 SSL_* 符号，BoringSSL 的行号启发式也匹配不上。
 *
 * 这里走 ERR_STRING_DATA 反查，链路如下：
 *   1. .rodata 里定位 "SSL_read\0" / "SSL_write\0" 字符串
 *   2. PT_DYNAMIC → DT_RELA，找 R_AARCH64_RELATIVE 且 r_addend == 字符串地址的条目
 *      r_offset 就是 ERR_STRING_DATA.string 字段的地址，往前 8 字节即 error code
 *   3. code 拆出 lib/func/reason（ERR_PACK 布局：lib<<24 | func<<12 | reason）
 *   4. .text 里扫 "mov w0, #20 (ERR_LIB_SSL)" + "mov w1, #func" 定位 SSLerr 调用点
 *   5. 从调用点向上回溯函数入口
 *
 * func 编号随 OpenSSL 版本变化（1.1.1h 里 SSL_read=223、SSL_write=208），
 * 所以第 2、3 步是运行时算的，不能写死。
 */

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint64_t entsize;
} elf64_rela_range;

static int elf64_find_rela_range(
    const uint8_t *base,
    size_t map_size,
    const Elf64_Ehdr *eh,
    const Elf64_Phdr *phdrs,
    elf64_rela_range *out
) {
    for (int p = 0; p < eh->e_phnum; p++) {
        if (phdrs[p].p_type != PT_DYNAMIC) continue;
        if (phdrs[p].p_offset + phdrs[p].p_filesz > map_size) return -1;
        if (phdrs[p].p_filesz < sizeof(Elf64_Dyn)) return -1;

        const Elf64_Dyn *dyn = (const Elf64_Dyn *)(base + phdrs[p].p_offset);
        size_t count = (size_t)(phdrs[p].p_filesz / sizeof(Elf64_Dyn));
        uint64_t rela_va = 0, rela_sz = 0, rela_ent = sizeof(Elf64_Rela);
        for (size_t i = 0; i < count && dyn[i].d_tag != DT_NULL; i++) {
            if (dyn[i].d_tag == DT_RELA) {
                rela_va = (uint64_t)dyn[i].d_un.d_ptr;
            } else if (dyn[i].d_tag == DT_RELASZ) {
                rela_sz = (uint64_t)dyn[i].d_un.d_val;
            } else if (dyn[i].d_tag == DT_RELAENT && dyn[i].d_un.d_val >= sizeof(Elf64_Rela)) {
                rela_ent = (uint64_t)dyn[i].d_un.d_val;
            }
        }
        if (rela_va == 0 || rela_sz < sizeof(Elf64_Rela)) return -1;

        uint64_t rela_off = 0;
        if (elf64_vaddr_to_offset(eh, phdrs, rela_va, 0, &rela_off) != 0) return -1;
        if (rela_off + rela_sz > map_size) return -1;

        out->offset = rela_off;
        out->size = rela_sz;
        out->entsize = rela_ent;
        return 0;
    }
    return -1;
}

static int openssl_string_to_va(
    const uint8_t *base,
    size_t map_size,
    const Elf64_Ehdr *eh,
    const Elf64_Phdr *phdrs,
    const char *name,
    uint64_t *out_va
) {
    size_t len = strlen(name) + 1;  /* 连结尾 NUL 一起匹配，避免 SSL_read 命中 SSL_read_ex */
    (void)map_size;
    const uint8_t *hit = (const uint8_t *)memmem(base, map_size, name, len);
    if (!hit) return -1;
    return elf64_offset_to_vaddr(eh, phdrs, (uint64_t)(hit - base), out_va);
}

static int openssl_err_func_code(
    const uint8_t *base,
    size_t map_size,
    const Elf64_Ehdr *eh,
    const Elf64_Phdr *phdrs,
    const elf64_rela_range *rela,
    uint64_t str_va,
    uint32_t *out_func
) {
    size_t count = (size_t)(rela->size / rela->entsize);
    for (size_t i = 0; i < count; i++) {
        const Elf64_Rela *r = (const Elf64_Rela *)(base + rela->offset + i * rela->entsize);
        if ((uint32_t)ELF64_R_TYPE(r->r_info) != R_AARCH64_RELATIVE) continue;
        if ((uint64_t)r->r_addend != str_va) continue;

        if (r->r_offset < 8) continue;
        uint64_t code_off = 0;
        if (elf64_vaddr_to_offset(eh, phdrs, (uint64_t)r->r_offset - 8, 0, &code_off) != 0) continue;
        if (code_off + sizeof(uint64_t) > map_size) continue;

        uint64_t code = 0;
        memcpy(&code, base + code_off, sizeof(code));
        uint32_t lib = (uint32_t)((code >> 24) & 0xffU);
        uint32_t func = (uint32_t)((code >> 12) & 0xfffU);
        if (lib != 20 /* ERR_LIB_SSL */ || func == 0) continue;

        *out_func = func;
        return 0;
    }
    return -1;
}

static size_t openssl_find_err_call_site(
    const uint32_t *words,
    size_t word_count,
    uint32_t func_code
) {
    for (size_t i = 0; i < word_count; i++) {
        if (words[i] != 0x52800280U) continue;  /* mov w0, #20 */
        for (size_t j = 1; j <= 8 && i + j < word_count; j++) {
            uint32_t ins = words[i + j];
            if ((ins & 0xffe0001fU) == 0x52800001U) {  /* mov w1, #imm */
                uint32_t imm = (ins >> 5) & 0xffffU;
                if (imm == func_code) return i + j;
                if (imm > 0xfffU) break;  /* 跑出函数码范围，不是同一次调用 */
            }
        }
    }
    return SIZE_MAX;
}

static int resolve_stripped_openssl_offsets(
    const char *path,
    uint64_t *out_write,
    uint64_t *out_read,
    uint64_t *out_sni
) {
    if (!path) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return -1;
    }
    /* 静态链入 OpenSSL 的 so 不可能很小；先按体积筛掉大量无关库，省掉 mmap 和全段扫 */
    if (st.st_size < (off_t)(256 * 1024)) {
        close(fd);
        return -1;
    }
    size_t map_size = (size_t)st.st_size;
    const uint8_t *base = (const uint8_t *)mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;

    int rc = -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
        eh->e_ident[EI_CLASS] == ELFCLASS64 &&
        eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf64_Phdr) <= map_size) {

        const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(base + eh->e_phoff);

        /* 先确认是 OpenSSL 1.1.x，别在无关 so 上白扫 */
        if (memmem(base, map_size, "OpenSSL 1.1.", 12) != NULL) {
            elf64_rela_range rela;
            if (elf64_find_rela_range(base, map_size, eh, phdrs, &rela) == 0) {
                uint64_t write_str = 0, read_str = 0;
                uint32_t write_func = 0, read_func = 0;
                if (openssl_string_to_va(base, map_size, eh, phdrs, "SSL_write", &write_str) == 0 &&
                    openssl_string_to_va(base, map_size, eh, phdrs, "SSL_read", &read_str) == 0 &&
                    openssl_err_func_code(base, map_size, eh, phdrs, &rela, write_str, &write_func) == 0 &&
                    openssl_err_func_code(base, map_size, eh, phdrs, &rela, read_str, &read_func) == 0) {

                    uint64_t text_off = 0, text_va = 0, text_sz = 0;
                    if (elf64_find_exec_range(base, map_size, eh, phdrs, &text_off, &text_va, &text_sz) == 0 &&
                        (text_off & 3ULL) == 0 && text_sz >= 256) {
                        const uint32_t *words = (const uint32_t *)(base + text_off);
                        size_t word_count = (size_t)(text_sz / 4ULL);

                        size_t write_site = openssl_find_err_call_site(words, word_count, write_func);
                        size_t read_site = openssl_find_err_call_site(words, word_count, read_func);

                        if (write_site != SIZE_MAX && read_site != SIZE_MAX) {
                            size_t write_start = openssl_scan_func_entry(words, write_site, 128);
                            size_t read_start = openssl_scan_func_entry(words, read_site, 128);
                            if (write_start != SIZE_MAX && read_start != SIZE_MAX &&
                                write_start != read_start) {
                                *out_write = text_off + (uint64_t)write_start * 4ULL;
                                *out_read = text_off + (uint64_t)read_start * 4ULL;
                                /* SSL_set_tlsext_host_name 常被内联，没有稳定入口；host 交给 ClientHello 解析 */
                                if (out_sni) *out_sni = 0;
                                rc = 0;
                            }
                        }
                    }
                }
            }
        }
    }

    munmap((void *)base, map_size);
    return rc;
}

static int resolve_cronet_offsets_for_sig(
    const char *path,
    const char *jni_sig,
    int slot_hdr,
    int slot_body,
    int slot_fin,
    uint64_t *out_create,
    uint64_t *out_resp_started,
    uint64_t *out_read_completed,
    uint64_t *out_succeeded
) {
    if (!path || !jni_sig || !jni_sig[0] || !ascii_strcasestr_contains(path, "cronet")) return -1;
    int max_slot = slot_hdr;
    if (slot_body > max_slot) max_slot = slot_body;
    if (slot_fin > max_slot) max_slot = slot_fin;
    if (slot_hdr < 0 || slot_body < 0 || slot_fin < 0 || max_slot >= 16) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return -1;
    }
    size_t map_size = (size_t)st.st_size;
    const uint8_t *base = (const uint8_t *)mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;

    int rc = -1;
    size_t sig_bytes = strlen(jni_sig) + 1;
    const uint8_t *sig_hit = (const uint8_t *)memmem(base, map_size, jni_sig, sig_bytes);
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;

    if (sig_hit &&
        memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
        eh->e_ident[EI_CLASS] == ELFCLASS64 &&
        eh->e_phoff + (size_t)eh->e_phnum * sizeof(Elf64_Phdr) <= map_size &&
        eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) <= map_size) {
        const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(base + eh->e_phoff);
        const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(base + eh->e_shoff);
        uint64_t sig_off = (uint64_t)(sig_hit - base);
        uint64_t sig_va = 0, text_off = 0, text_va = 0, text_sz = 0;

        if (elf64_offset_to_vaddr(eh, phdrs, sig_off, &sig_va) == 0 &&
            elf64_find_exec_range(base, map_size, eh, phdrs, &text_off, &text_va, &text_sz) == 0 &&
            (text_off & 3ULL) == 0) {
            uint64_t fn_va = 0;

            // Search SHT_RELA for R_AARCH64_RELATIVE (0x403) pointing to sig_va + adjacent fn_ptr
            for (int i = 0; i < eh->e_shnum && fn_va == 0; i++) {
                if (shdrs[i].sh_type != SHT_RELA) continue;
                if (shdrs[i].sh_offset + shdrs[i].sh_size > map_size) continue;
                const Elf64_Rela *relas = (const Elf64_Rela *)(base + shdrs[i].sh_offset);
                size_t rcnt = shdrs[i].sh_size / sizeof(Elf64_Rela);
                for (size_t r = 0; r < rcnt; r++) {
                    if (ELF64_R_TYPE(relas[r].r_info) == 0x403 && (uint64_t)relas[r].r_addend == sig_va) {
                        uint64_t sig_slot_va = relas[r].r_offset;
                        for (size_t r2 = (r > 4 ? r - 4 : 0); r2 < rcnt && r2 < r + 8; r2++) {
                            if (ELF64_R_TYPE(relas[r2].r_info) == 0x403 &&
                                relas[r2].r_offset == sig_slot_va + 8ULL) {
                                fn_va = (uint64_t)relas[r2].r_addend;
                                break;
                            }
                        }
                        if (fn_va == 0) {
                            for (size_t r2 = 0; r2 < rcnt; r2++) {
                                if (ELF64_R_TYPE(relas[r2].r_info) == 0x403 &&
                                    relas[r2].r_offset == sig_slot_va + 8ULL) {
                                    fn_va = (uint64_t)relas[r2].r_addend;
                                    break;
                                }
                            }
                        }
                        if (fn_va != 0) break;
                    }
                }
            }

            // Fallback for .relr.dyn / static data tables: scan writable PT_LOAD for raw sig_va pointer
            if (fn_va == 0) {
                for (int p = 0; p < eh->e_phnum && fn_va == 0; p++) {
                    if (phdrs[p].p_type != PT_LOAD || (phdrs[p].p_flags & PF_W) == 0) continue;
                    if (phdrs[p].p_offset + phdrs[p].p_filesz > map_size) continue;
                    size_t cnt = phdrs[p].p_filesz / sizeof(uint64_t);
                    const uint64_t *ptrs = (const uint64_t *)(base + phdrs[p].p_offset);
                    for (size_t u = 0; u + 1 < cnt; u++) {
                        if (ptrs[u] == sig_va &&
                            ptrs[u + 1] >= text_va &&
                            ptrs[u + 1] < text_va + text_sz) {
                            fn_va = ptrs[u + 1];
                            break;
                        }
                    }
                }
            }

            if (fn_va >= text_va && fn_va + 16 < text_va + text_sz && (fn_va & 3ULL) == 0) {
                const uint32_t *words = (const uint32_t *)(base + text_off);
                size_t word_count = (size_t)(text_sz / 4ULL);
                size_t fn_idx = (size_t)((fn_va - text_va) / 4ULL);

                for (size_t k = fn_idx; k < word_count && k < fn_idx + 128; k++) {
                    if (words[k] == 0xd65f03c0U) break;
                    int64_t c_idx_s = aarch64_bl_target_idx(words, k, word_count);
                    if (c_idx_s < 0) continue;
                    size_t c_idx = (size_t)c_idx_s;

                    size_t m_end = (c_idx + 64 < word_count) ? (c_idx + 64) : word_count;
                    for (size_t m = c_idx; m + 1 < m_end; m++) {
                        uint32_t w0 = words[m];
                        uint32_t w1 = words[m + 1];
                        if ((w0 & 0x9f000000U) != 0x90000000U || (w1 & 0xff800000U) != 0x91000000U) {
                            continue;
                        }
                        uint32_t rd0 = w0 & 0x1fU;
                        uint32_t rd1 = w1 & 0x1fU;
                        uint32_t rn1 = (w1 >> 5) & 0x1fU;
                        if (rd0 != rn1 || rd0 != rd1) continue;

                        uint64_t immlo = (w0 >> 29) & 0x3ULL;
                        uint64_t immhi = (w0 >> 5) & 0x7ffffULL;
                        int64_t imm21 = (int64_t)((immhi << 2) | immlo);
                        if (imm21 & (1LL << 20)) imm21 -= (1LL << 21);
                        uint64_t pc_va = text_va + (uint64_t)m * 4ULL;
                        int64_t page = (int64_t)(pc_va & ~0xFFFULL) + (imm21 << 12);
                        uint64_t imm12 = (w1 >> 10) & 0xfffULL;
                        if ((w1 >> 22) & 1U) imm12 <<= 12;
                        uint64_t vt_va = (uint64_t)(page + (int64_t)imm12);

                        uint64_t vt_off = 0;
                        if (elf64_vaddr_to_offset(eh, phdrs, vt_va, 0, &vt_off) != 0 ||
                            vt_off + (size_t)(max_slot + 1) * sizeof(int32_t) > map_size) {
                            continue;
                        }

                        const int32_t *slots = (const int32_t *)(base + vt_off);
                        uint64_t targets[16];
                        int valid_vt = 1;
                        for (int s = 0; s <= max_slot; s++) {
                            if (slots[s] == 0) {
                                valid_vt = 0;
                                break;
                            }
                            uint64_t t = (uint64_t)((int64_t)vt_va + (int64_t)slots[s]);
                            if (t < text_va || t >= text_va + text_sz || (t & 3ULL) != 0) {
                                valid_vt = 0;
                                break;
                            }
                            size_t t_idx = (size_t)((t - text_va) / 4ULL);
                            if (!aarch64_is_likely_func_entry(words[t_idx])) {
                                valid_vt = 0;
                                break;
                            }
                            targets[s] = t;
                        }
                        if (!valid_vt) continue;

                        uint64_t req_ctor_va = 0;
                        size_t q_end = (c_idx + 80 < word_count) ? (c_idx + 80) : word_count;
                        for (size_t q = m; q < q_end; q++) {
                            if (words[q] == 0xd65f03c0U) break;
                            int64_t rq_idx = aarch64_bl_target_idx(words, q, word_count);
                            if (rq_idx < 0) continue;
                            size_t z_start = (q > m + 10) ? (q - 10) : m;
                            for (size_t z = z_start; z < q; z++) {
                                // Match MOV X2, Xn (0xaa0003e2 | (n << 16))
                                if ((words[z] & 0xffe0ffffU) == 0xaa0003e2U && ((words[z] >> 16) & 0x1fU) != 31U) {
                                    req_ctor_va = text_va + (uint64_t)rq_idx * 4ULL;
                                    break;
                                }
                            }
                            if (req_ctor_va != 0) break;
                        }

                        if (req_ctor_va != 0) {
                            uint64_t off_create = 0, off_hdr = 0, off_body = 0, off_fin = 0;
                            if (elf64_vaddr_to_offset(eh, phdrs, req_ctor_va, 1, &off_create) == 0 &&
                                elf64_vaddr_to_offset(eh, phdrs, targets[slot_hdr], 1, &off_hdr) == 0 &&
                                elf64_vaddr_to_offset(eh, phdrs, targets[slot_body], 1, &off_body) == 0 &&
                                elf64_vaddr_to_offset(eh, phdrs, targets[slot_fin], 1, &off_fin) == 0) {
                                *out_create = off_create;
                                *out_resp_started = off_hdr;
                                *out_read_completed = off_body;
                                *out_succeeded = off_fin;
                                rc = 0;
                                break;
                            }
                        }
                    }
                    if (rc == 0) break;
                }
            }
        }
    }

    munmap((void *)base, map_size);
    return rc;
}

static int resolve_cronet_offsets(
    const char *path,
    uint64_t *out_create,
    uint64_t *out_resp_started,
    uint64_t *out_read_completed,
    uint64_t *out_succeeded
) {
    for (int i = 0; i < g_custom_cronet_sig_count; i++) {
        if (resolve_cronet_offsets_for_sig(
                path, g_custom_cronet_sigs[i],
                g_cronet_slot_hdr, g_cronet_slot_body, g_cronet_slot_fin,
                out_create, out_resp_started, out_read_completed, out_succeeded
            ) == 0) {
            return 0;
        }
    }
    static const char default_sig[] = "(Ljava/lang/Object;JLjava/lang/String;IZZZIZIIJ)J";
    return resolve_cronet_offsets_for_sig(
        path, default_sig,
        g_cronet_slot_hdr, g_cronet_slot_body, g_cronet_slot_fin,
        out_create, out_resp_started, out_read_completed, out_succeeded
    );
}
#endif



typedef struct {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
} raw_bpf_map_def;

typedef struct {
    char name[64];
    int fd;
    uint32_t sym_idx;
} loaded_map;

typedef struct {
    int target_uid_map_fd;
    int events_map_fd;
    int cronet_abi_map_fd;
    int prog_write_fd;
    int prog_read_enter_fd;
    int prog_read_exit_fd;
    int prog_sni_fd;
    int prog_cronet_create_fd;
    int prog_cronet_resp_started_fd;
    int prog_cronet_read_completed_fd;
    int prog_cronet_succeeded_fd;
    int prog_reg_natives_fd;
    int prog_reg_natives_exit_fd;
    int prog_jni_arg_fd;
    int prog_jni_ret_fd;
    int prog_array_region_fd;
    int jni_reg_args_map_fd;
    int jni_addr_map_fd;
} bpf_bundle;

static int try_bpf_prog_load(
    struct bpf_insn *insns,
    size_t insn_count,
    uint32_t kver,
    uint32_t log_level,
    char *log_buf,
    size_t log_buf_size
) {
    union bpf_attr pattr;
    memset(&pattr, 0, sizeof(pattr));
    pattr.prog_type = BPF_PROG_TYPE_KPROBE;
    pattr.insn_cnt = (uint32_t)insn_count;
    pattr.insns = (uint64_t)(uintptr_t)insns;
    pattr.license = (uint64_t)(uintptr_t)"GPL";
    pattr.kern_version = kver;
    pattr.log_level = log_level;
    pattr.log_size = (uint32_t)log_buf_size;
    pattr.log_buf = (uint64_t)(uintptr_t)log_buf;
    if (log_buf && log_buf_size > 0) {
        log_buf[0] = '\0';
    }

    int pfd = sys_bpf(BPF_PROG_LOAD, &pattr, sizeof(pattr));
    if (pfd < 0 && (errno == EINVAL || errno == E2BIG)) {
        // Fallback for Android Linux 5.4 kernels lacking bpf_probe_read_user (helper #112 -> #4)
        int patched = 0;
        for (size_t k = 0; k < insn_count; k++) {
            if (insns[k].code == (BPF_JMP | BPF_CALL) && insns[k].imm == 112) {
                insns[k].imm = 4;
                patched = 1;
            }
        }
        if (patched) {
            if (log_buf && log_buf_size > 0) {
                log_buf[0] = '\0';
            }
            pfd = sys_bpf(BPF_PROG_LOAD, &pattr, sizeof(pattr));
        }
    }
    return pfd;
}

static void raise_memlock_rlimit(void) {
    struct rlimit rl;
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        return;
    }
    rl.rlim_cur = 64ULL * 1024ULL * 1024ULL;
    rl.rlim_max = 64ULL * 1024ULL * 1024ULL;
    setrlimit(RLIMIT_MEMLOCK, &rl);
}

static int load_bpf_object(const uint8_t *obj, size_t obj_len, int num_cpus, bpf_bundle *out) {
    memset(out, -1, sizeof(*out));
    if (obj_len < sizeof(Elf64_Ehdr)) return -1;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)obj;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "ERR:invalid_bpf_elf\n");
        return -1;
    }

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(obj + eh->e_shoff);
    const char *shstrtab = (const char *)(obj + shdrs[eh->e_shstrndx].sh_offset);

    int maps_shndx = -1;
    int symtab_shndx = -1;
    for (int i = 0; i < eh->e_shnum; i++) {
        const char *sname = shstrtab + shdrs[i].sh_name;
        if (strcmp(sname, "maps") == 0) maps_shndx = i;
        if (shdrs[i].sh_type == SHT_SYMTAB) symtab_shndx = i;
    }
    if (maps_shndx < 0 || symtab_shndx < 0) {
        fprintf(stderr, "ERR:missing_maps_or_symtab\n");
        return -1;
    }

    const Elf64_Shdr *sym_sh = &shdrs[symtab_shndx];
    const Elf64_Sym *syms = (const Elf64_Sym *)(obj + sym_sh->sh_offset);
    size_t sym_count = sym_sh->sh_size / sizeof(Elf64_Sym);
    const char *strtab = (const char *)(obj + shdrs[sym_sh->sh_link].sh_offset);
    const uint8_t *maps_data = obj + shdrs[maps_shndx].sh_offset;

    loaded_map maps[16];
    int map_count = 0;

    for (size_t s = 0; s < sym_count && map_count < 16; s++) {
        if (syms[s].st_shndx != maps_shndx) continue;
        if (ELF64_ST_TYPE(syms[s].st_info) == STT_SECTION) continue;
        if (syms[s].st_value + sizeof(raw_bpf_map_def) > shdrs[maps_shndx].sh_size) continue;

        const raw_bpf_map_def *def = (const raw_bpf_map_def *)(maps_data + syms[s].st_value);
        const char *mname = strtab + syms[s].st_name;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.map_type = def->type;
        attr.key_size = def->key_size;
        attr.value_size = def->value_size;
        attr.max_entries = (def->type == BPF_MAP_TYPE_PERF_EVENT_ARRAY && def->max_entries == 0)
            ? (uint32_t)num_cpus
            : def->max_entries;
        attr.map_flags = def->map_flags;
        strncpy(attr.map_name, mname, sizeof(attr.map_name) - 1);

        int fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0) {
            fprintf(stderr, "ERR:bpf_map_create(%s):errno=%d(%s)\n", mname, errno, strerror(errno));
            return -1;
        }
        snprintf(maps[map_count].name, sizeof(maps[map_count].name), "%s", mname);
        maps[map_count].fd = fd;
        maps[map_count].sym_idx = (uint32_t)s;

        if (strcmp(mname, "target_uid_map") == 0) out->target_uid_map_fd = fd;
        else if (strcmp(mname, "events") == 0) out->events_map_fd = fd;
        else if (strcmp(mname, "cronet_abi_map") == 0) out->cronet_abi_map_fd = fd;
        else if (strcmp(mname, "jni_reg_args") == 0) out->jni_reg_args_map_fd = fd;
        else if (strcmp(mname, "jni_addr_map") == 0) out->jni_addr_map_fd = fd;
        map_count++;
    }

    uint32_t kver = detect_kernel_version_code();
    const char *prog_secs[] = {
        "uprobe/ssl_write",
        "uprobe/ssl_read_enter",
        "uretprobe/ssl_read_exit",
        "uprobe/ssl_set_sni",
        "uprobe/cronet_create",
        "uprobe/cronet_resp_started",
        "uprobe/cronet_read_completed",
        "uprobe/cronet_succeeded",
        "uprobe/reg_natives",
        "uretprobe/reg_natives_exit",
        "uprobe/jni_arg",
        "uretprobe/jni_ret",
        "uprobe/array_region"
    };
    int *prog_fds[] = {
        &out->prog_write_fd,
        &out->prog_read_enter_fd,
        &out->prog_read_exit_fd,
        &out->prog_sni_fd,
        &out->prog_cronet_create_fd,
        &out->prog_cronet_resp_started_fd,
        &out->prog_cronet_read_completed_fd,
        &out->prog_cronet_succeeded_fd,
        &out->prog_reg_natives_fd,
        &out->prog_reg_natives_exit_fd,
        &out->prog_jni_arg_fd,
        &out->prog_jni_ret_fd,
        &out->prog_array_region_fd
    };
    const int prog_required[] = {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const int prog_count = (int)(sizeof(prog_secs) / sizeof(prog_secs[0]));

    for (int p = 0; p < prog_count; p++) {
        int sec_idx = -1;
        for (int i = 0; i < eh->e_shnum; i++) {
            if (strcmp(shstrtab + shdrs[i].sh_name, prog_secs[p]) == 0) {
                sec_idx = i;
                break;
            }
        }
        if (sec_idx < 0 || shdrs[sec_idx].sh_size == 0) {
            if (!prog_required[p]) {
                fprintf(stderr, "WARN:missing_optional_prog_section(%s)\n", prog_secs[p]);
                continue;
            }
            fprintf(stderr, "ERR:missing_prog_section(%s)\n", prog_secs[p]);
            return -1;
        }

        size_t insn_bytes = shdrs[sec_idx].sh_size;
        size_t insn_count = insn_bytes / sizeof(struct bpf_insn);
        struct bpf_insn *insns = (struct bpf_insn *)malloc(insn_bytes);
        if (!insns) return -1;
        memcpy(insns, obj + shdrs[sec_idx].sh_offset, insn_bytes);

        // Apply relocations matching this section
        for (int i = 0; i < eh->e_shnum; i++) {
            if (shdrs[i].sh_type != SHT_REL) continue;
            if ((int)shdrs[i].sh_info != sec_idx) continue;

            const Elf64_Rel *rels = (const Elf64_Rel *)(obj + shdrs[i].sh_offset);
            size_t rel_count = shdrs[i].sh_size / sizeof(Elf64_Rel);
            for (size_t r = 0; r < rel_count; r++) {
                uint32_t rtype = (uint32_t)ELF64_R_TYPE(rels[r].r_info);
                uint32_t rsym = (uint32_t)ELF64_R_SYM(rels[r].r_info);
                size_t insn_idx = (size_t)(rels[r].r_offset / sizeof(struct bpf_insn));
                if (rtype != R_BPF_64_64 || insn_idx + 1 >= insn_count) continue;

                int found_fd = -1;
                for (int m = 0; m < map_count; m++) {
                    if (maps[m].sym_idx == rsym) {
                        found_fd = maps[m].fd;
                        break;
                    }
                }
                if (found_fd < 0) {
                    free(insns);
                    fprintf(stderr, "ERR:reloc_map_not_found(sym=%u)\n", rsym);
                    return -1;
                }
                insns[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
                insns[insn_idx].imm = found_fd;
                insns[insn_idx + 1].imm = 0;
            }
        }

        // Load without verifier log overhead first so log buffer overflow never triggers ENOSPC on valid programs.
        int pfd = try_bpf_prog_load(insns, insn_count, kver, 0, NULL, 0);
        if (pfd < 0) {
            int load_errno = errno;
            const size_t diag_size = 262144;
            char *diag_buf = (char *)calloc(1, diag_size);
            if (diag_buf) {
                int diag_pfd = try_bpf_prog_load(insns, insn_count, kver, 1, diag_buf, diag_size);
                if (diag_pfd >= 0) {
                    pfd = diag_pfd;
                } else {
                    for (size_t idx = 0; idx < diag_size && diag_buf[idx]; idx++) {
                        if (diag_buf[idx] == '\n' || diag_buf[idx] == '\r') {
                            diag_buf[idx] = ' ';
                        }
                    }
                    fprintf(stderr, "%s:bpf_prog_load(%s):errno=%d(%s):%.2048s\n",
                            prog_required[p] ? "ERR" : "WARN",
                            prog_secs[p], load_errno, strerror(load_errno), diag_buf);
                }
                free(diag_buf);
            } else {
                fprintf(stderr, "%s:bpf_prog_load(%s):errno=%d(%s)\n",
                        prog_required[p] ? "ERR" : "WARN",
                        prog_secs[p], load_errno, strerror(load_errno));
            }
        }

        free(insns);
        if (pfd < 0) {
            if (!prog_required[p]) {
                continue;
            }
            return -1;
        }
        *(prog_fds[p]) = pfd;
    }

    return 0;
}

static int read_int_file(const char *path, int *out_val) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = 0;
    int ok = fscanf(f, "%d", &v) == 1 ? 0 : -1;
    fclose(f);
    if (ok == 0) *out_val = v;
    return ok;
}

static void remove_tracefs_uprobe_suffix(const char *probe_suffix) {
    if (!g_tracefs_dir[0] || !g_probe_prefix[0] || !probe_suffix || !probe_suffix[0]) return;
    char events_path[300];
    snprintf(events_path, sizeof(events_path), "%s/uprobe_events", g_tracefs_dir);
    int fd = open(events_path, O_WRONLY | O_APPEND);
    if (fd >= 0) {
        char cmd[128];
        int n = snprintf(cmd, sizeof(cmd), "-:uprobes/%s_%s\n", g_probe_prefix, probe_suffix);
        if (n > 0) write(fd, cmd, (size_t)n);
        close(fd);
    }
}

static void cleanup_tracefs_uprobes(void) {
    if (!g_tracefs_dir[0] || !g_probe_prefix[0]) return;
    char events_path[300];
    snprintf(events_path, sizeof(events_path), "%s/uprobe_events", g_tracefs_dir);
    int fd = open(events_path, O_WRONLY | O_APPEND);
    if (fd >= 0) {
        char cmd[512];
        int n = snprintf(cmd, sizeof(cmd), "-:uprobes/%s_w\n-:uprobes/%s_rw\n-:uprobes/%s_rr\n-:uprobes/%s_sni\n",
                         g_probe_prefix, g_probe_prefix, g_probe_prefix, g_probe_prefix);
        if (n > 0) write(fd, cmd, (size_t)n);

        for (int i = 0; i < g_attached_lib_count && i < MAX_ATTACHED_LIBS; i++) {
            n = snprintf(cmd, sizeof(cmd),
                         "-:uprobes/%s_w_%d\n-:uprobes/%s_rw_%d\n-:uprobes/%s_rr_%d\n-:uprobes/%s_sni_%d\n"
                         "-:uprobes/%s_cr_req_%d\n-:uprobes/%s_cr_hdr_%d\n-:uprobes/%s_cr_body_%d\n-:uprobes/%s_cr_fin_%d\n",
                         g_probe_prefix, i, g_probe_prefix, i, g_probe_prefix, i, g_probe_prefix, i,
                         g_probe_prefix, i, g_probe_prefix, i, g_probe_prefix, i, g_probe_prefix, i);
            if (n > 0) write(fd, cmd, (size_t)n);
        }
        close(fd);
    }
}

static int attach_uprobe_pmu_or_tracefs(
    const char *lib_path,
    uint64_t file_offset,
    int is_retprobe,
    const char *probe_suffix,
    int prog_fd,
    int num_cpus,
    int *perf_fds,
    int *perf_fd_count
) {
    // Method 1: PMU uprobe via /sys/bus/event_source/devices/uprobe/type
    int pmu_type = -1;
    if (read_int_file("/sys/bus/event_source/devices/uprobe/type", &pmu_type) == 0 && pmu_type > 0) {
        int ret_bit = 0;
        FILE *ff = fopen("/sys/bus/event_source/devices/uprobe/format/retprobe", "r");
        if (ff) {
            char line[64] = {0};
            if (fgets(line, sizeof(line), ff)) {
                int b = 0;
                if (sscanf(line, "config:%d", &b) == 1) ret_bit = b;
            }
            fclose(ff);
        }

        int opened = 0;
        for (int cpu = 0; cpu < num_cpus; cpu++) {
            struct perf_event_attr attr;
            memset(&attr, 0, sizeof(attr));
            attr.type = (uint32_t)pmu_type;
            attr.size = sizeof(attr);
            attr.config = is_retprobe ? (1ULL << ret_bit) : 0ULL;
            attr.config1 = (uint64_t)(uintptr_t)lib_path;
            attr.config2 = file_offset;

            int pfd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
            if (pfd < 0) {
                // Tolerate hotplugged offline CPUs; if parameters are invalid, all CPUs fail and opened stays 0.
                continue;
            }
            if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0 ||
                ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
                close(pfd);
                opened = -1;
                break;
            }
            perf_fds[*perf_fd_count + opened] = pfd;
            opened = 1;
            break;
        }
        if (opened > 0) {
            *perf_fd_count += opened;
            return 0;
        }
    }

    // Method 2: Tracefs uprobe_events fallback
    const char *tracefs = find_tracefs_dir();
    if (!tracefs) {
        set_last_attach_err("no_uprobe_pmu_or_tracefs");
        fprintf(stderr, "WARN:no_uprobe_pmu_or_tracefs\n");
        return -1;
    }
    snprintf(g_tracefs_dir, sizeof(g_tracefs_dir), "%s", tracefs);

    char uprobe_events_path[300];
    snprintf(uprobe_events_path, sizeof(uprobe_events_path), "%s/uprobe_events", tracefs);
    int ufd = open(uprobe_events_path, O_WRONLY | O_APPEND);
    if (ufd < 0) {
        int err = errno;
        char msg[256];
        snprintf(msg, sizeof(msg), "open_uprobe_events:errno=%d(%s)", err, strerror(err));
        set_last_attach_err(msg);
        fprintf(stderr, "WARN:%s\n", msg);
        return -1;
    }

    char ev_line[1024];
    int n = snprintf(ev_line, sizeof(ev_line), "%c:uprobes/%s_%s %s:0x%llx\n",
                     is_retprobe ? 'r' : 'p',
                     g_probe_prefix, probe_suffix,
                     lib_path, (unsigned long long)file_offset);
    ssize_t wr = write(ufd, ev_line, (size_t)n);
    int werrno = errno;
    close(ufd);
    if (wr < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "write_uprobe_events:errno=%d(%s)", werrno, strerror(werrno));
        set_last_attach_err(msg);
        fprintf(stderr, "WARN:%s\n", msg);
        return -1;
    }

    char id_path[384];
    snprintf(id_path, sizeof(id_path), "%s/events/uprobes/%s_%s/id", tracefs, g_probe_prefix, probe_suffix);
    int tp_id = -1;
    if (read_int_file(id_path, &tp_id) != 0 || tp_id <= 0) {
        remove_tracefs_uprobe_suffix(probe_suffix);
        char msg[256];
        snprintf(msg, sizeof(msg), "read_tracepoint_id(%s_%s)", g_probe_prefix, probe_suffix);
        set_last_attach_err(msg);
        fprintf(stderr, "WARN:%s\n", msg);
        return -1;
    }

    int opened = 0;
    int last_open_errno = 0;
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_TRACEPOINT;
        attr.size = sizeof(attr);
        attr.config = (uint64_t)tp_id;

        int pfd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pfd < 0) {
            last_open_errno = errno;
            continue;
        }
        if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0 ||
            ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
            int ioerr = errno;
            close(pfd);
            remove_tracefs_uprobe_suffix(probe_suffix);
            char msg[256];
            snprintf(msg, sizeof(msg), "ioc_set_bpf:errno=%d(%s)", ioerr, strerror(ioerr));
            set_last_attach_err(msg);
            fprintf(stderr, "WARN:%s\n", msg);
            return -1;
        }
        perf_fds[*perf_fd_count + opened] = pfd;
        opened = 1;
        break;
    }
    if (opened == 0) {
        remove_tracefs_uprobe_suffix(probe_suffix);
        char msg[256];
        snprintf(msg, sizeof(msg), "perf_event_open_tp(%s):errno=%d(%s)",
                 lib_path, last_open_errno, strerror(last_open_errno));
        set_last_attach_err(msg);
        fprintf(stderr, "WARN:%s\n", msg);
        return -1;
    }
    *perf_fd_count += opened;
    return 0;
}

typedef struct {
    int has_ssl;
    const char *ssl_source;
    uint64_t off_write;
    uint64_t off_read;
    uint64_t off_sni;
    int has_cronet;
    const char *cronet_source;
    uint64_t off_cr_req;
    uint64_t off_cr_hdr;
    uint64_t off_cr_body;
    uint64_t off_cr_fin;
} library_probe_result;

static void inspect_library_offsets(const char *path, int check_cronet, library_probe_result *out) {
    memset(out, 0, sizeof(*out));
    out->ssl_source = "none";
    out->cronet_source = "none";

    for (int r = 0; r < g_ssl_rule_count; r++) {
        if (strstr(path, g_ssl_rules[r].lib_substr) != NULL &&
            g_ssl_rules[r].write_off != 0 && g_ssl_rules[r].read_off != 0) {
            out->off_write = g_ssl_rules[r].write_off;
            out->off_read = g_ssl_rules[r].read_off;
            out->off_sni = g_ssl_rules[r].sni_off;
            out->has_ssl = 1;
            out->ssl_source = "rule";
            break;
        }
    }
    if (!out->has_ssl) {
        if (resolve_elf_symbol_offset(path, "SSL_write", &out->off_write) == 0 &&
            resolve_elf_symbol_offset(path, "SSL_read", &out->off_read) == 0) {
            out->has_ssl = 1;
            out->ssl_source = "dynsym";
            resolve_elf_symbol_offset(path, "SSL_set_tlsext_host_name", &out->off_sni);
        }
#if defined(__LP64__) && defined(__aarch64__)
        else if (resolve_stripped_boringssl_offsets(path, &out->off_write, &out->off_read, &out->off_sni) == 0) {
            out->has_ssl = 1;
            out->ssl_source = "stripped_heuristic";
        }
        else if (resolve_stripped_openssl_offsets(path, &out->off_write, &out->off_read, &out->off_sni) == 0) {
            out->has_ssl = 1;
            out->ssl_source = "openssl_heuristic";
        }
#endif
    }

    if (out->has_ssl) {
        fprintf(stderr,
                "INFO:ssl-offsets %s source=%s write=0x%llx read=0x%llx sni=0x%llx\n",
                path, out->ssl_source,
                (unsigned long long)out->off_write,
                (unsigned long long)out->off_read,
                (unsigned long long)out->off_sni);
    }

#if defined(__LP64__) && defined(__aarch64__)
    if (check_cronet) {
        for (int r = 0; r < g_cronet_rule_count; r++) {
            if (strstr(path, g_cronet_rules[r].lib_substr) != NULL &&
                g_cronet_rules[r].create_off != 0 && g_cronet_rules[r].hdr_off != 0 &&
                g_cronet_rules[r].body_off != 0 && g_cronet_rules[r].fin_off != 0) {
                out->off_cr_req = g_cronet_rules[r].create_off;
                out->off_cr_hdr = g_cronet_rules[r].hdr_off;
                out->off_cr_body = g_cronet_rules[r].body_off;
                out->off_cr_fin = g_cronet_rules[r].fin_off;
                out->has_cronet = 1;
                out->cronet_source = "rule";
                break;
            }
        }
        if (!out->has_cronet &&
            resolve_cronet_offsets(path, &out->off_cr_req, &out->off_cr_hdr, &out->off_cr_body, &out->off_cr_fin) == 0) {
            out->has_cronet = 1;
            out->cronet_source = "elf_heuristic";
        }
    }
#else
    (void)check_cronet;
#endif
}

static int try_attach_library(const char *path, bpf_bundle *bundle, int num_cpus) {
    if (!path || !path[0] || !file_exists_nonempty(path)) return -1;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) return -1;

    for (int i = 0; i < g_attached_lib_count; i++) {
        if ((g_attached_libs[i].dev == st.st_dev && g_attached_libs[i].ino == st.st_ino) ||
            strcmp(g_attached_libs[i].path, path) == 0) {
            return 0; // already attached
        }
    }

    if (g_attached_lib_count >= MAX_ATTACHED_LIBS) {
        return -1;
    }

#if defined(__LP64__) && defined(__aarch64__)
    int cronet_progs_ready = (
        bundle->prog_cronet_create_fd >= 0 &&
        bundle->prog_cronet_resp_started_fd >= 0 &&
        bundle->prog_cronet_read_completed_fd >= 0 &&
        bundle->prog_cronet_succeeded_fd >= 0
    );
#else
    int cronet_progs_ready = 0;
#endif

    library_probe_result probe;
    inspect_library_offsets(path, cronet_progs_ready, &probe);

    int has_ssl = probe.has_ssl;
    uint64_t off_write = probe.off_write;
    uint64_t off_read = probe.off_read;
    uint64_t off_sni = probe.off_sni;
#if defined(__LP64__) && defined(__aarch64__)
    int has_cronet = probe.has_cronet;
    uint64_t off_cr_req = probe.off_cr_req;
    uint64_t off_cr_hdr = probe.off_cr_hdr;
    uint64_t off_cr_body = probe.off_cr_body;
    uint64_t off_cr_fin = probe.off_cr_fin;
#endif

    if (!has_ssl && !probe.has_cronet) {
        return -1;
    }

    int idx = g_attached_lib_count;
    int fd_cnt = 0;
    int ssl_attached = 0;
    int cronet_attached = 0;

    if (has_ssl) {
        char suf_w[32], suf_rw[32], suf_rr[32], suf_sni[32];
        snprintf(suf_w, sizeof(suf_w), "w_%d", idx);
        snprintf(suf_rw, sizeof(suf_rw), "rw_%d", idx);
        snprintf(suf_rr, sizeof(suf_rr), "rr_%d", idx);
        snprintf(suf_sni, sizeof(suf_sni), "sni_%d", idx);

        int rc1 = attach_uprobe_pmu_or_tracefs(path, off_write, 0, suf_w, bundle->prog_write_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt);
        int rc2 = (rc1 == 0) ? attach_uprobe_pmu_or_tracefs(path, off_read, 0, suf_rw, bundle->prog_read_enter_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt) : -1;
        int rc3 = (rc2 == 0) ? attach_uprobe_pmu_or_tracefs(path, off_read, 1, suf_rr, bundle->prog_read_exit_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt) : -1;

        if (rc1 == 0 && rc2 == 0 && rc3 == 0) {
            ssl_attached = 1;
            if (bundle->prog_sni_fd >= 0 && off_sni != 0) {
                attach_uprobe_pmu_or_tracefs(
                    path, off_sni, 0, suf_sni, bundle->prog_sni_fd, num_cpus,
                    g_attached_libs[idx].uprobe_fds, &fd_cnt
                );
            }
        } else {
            for (int k = 0; k < fd_cnt; k++) {
                close(g_attached_libs[idx].uprobe_fds[k]);
            }
            fd_cnt = 0;
            remove_tracefs_uprobe_suffix(suf_w);
            remove_tracefs_uprobe_suffix(suf_rw);
            remove_tracefs_uprobe_suffix(suf_rr);
        }
    }

#if defined(__LP64__) && defined(__aarch64__)
    if (has_cronet) {
        int base_fd_cnt = fd_cnt;
        char suf_req[32], suf_hdr[32], suf_body[32], suf_fin[32];
        snprintf(suf_req, sizeof(suf_req), "cr_req_%d", idx);
        snprintf(suf_hdr, sizeof(suf_hdr), "cr_hdr_%d", idx);
        snprintf(suf_body, sizeof(suf_body), "cr_body_%d", idx);
        snprintf(suf_fin, sizeof(suf_fin), "cr_fin_%d", idx);

        int cr1 = attach_uprobe_pmu_or_tracefs(path, off_cr_req, 0, suf_req, bundle->prog_cronet_create_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt);
        int cr2 = (cr1 == 0) ? attach_uprobe_pmu_or_tracefs(path, off_cr_hdr, 0, suf_hdr, bundle->prog_cronet_resp_started_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt) : -1;
        int cr3 = (cr2 == 0) ? attach_uprobe_pmu_or_tracefs(path, off_cr_body, 0, suf_body, bundle->prog_cronet_read_completed_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt) : -1;
        int cr4 = (cr3 == 0) ? attach_uprobe_pmu_or_tracefs(path, off_cr_fin, 0, suf_fin, bundle->prog_cronet_succeeded_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt) : -1;

        if (cr1 == 0 && cr2 == 0 && cr3 == 0 && cr4 == 0) {
            cronet_attached = 1;
        } else {
            for (int k = base_fd_cnt; k < fd_cnt; k++) {
                close(g_attached_libs[idx].uprobe_fds[k]);
            }
            fd_cnt = base_fd_cnt;
            remove_tracefs_uprobe_suffix(suf_req);
            remove_tracefs_uprobe_suffix(suf_hdr);
            remove_tracefs_uprobe_suffix(suf_body);
            remove_tracefs_uprobe_suffix(suf_fin);
        }
    }
#endif

    if (!ssl_attached && !cronet_attached) {
        return -1;
    }

    snprintf(g_attached_libs[idx].path, sizeof(g_attached_libs[idx].path), "%s", path);
    g_attached_libs[idx].dev = st.st_dev;
    g_attached_libs[idx].ino = st.st_ino;
    g_attached_libs[idx].off_write = off_write;
    g_attached_libs[idx].off_read = off_read;
    g_attached_libs[idx].uprobe_fd_count = fd_cnt;
    g_attached_lib_count++;

    if (ssl_attached) {
        fprintf(stderr, "ATTACHED:%s\n", path);
    }
    if (cronet_attached) {
        fprintf(stderr, "ATTACHED_CRONET:%s\n", path);
    }
    fflush(stderr);
    return 1;
}

static int scan_and_attach_lib_dirs(bpf_bundle *bundle, int num_cpus) {
    int attached = 0;
    for (int d = 0; d < g_lib_dir_count; d++) {
        DIR *dir = opendir(g_lib_dirs[d]);
        if (!dir) continue;
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] == '.') continue;
            size_t nlen = strlen(de->d_name);
            if (nlen < 3 || strcmp(de->d_name + nlen - 3, ".so") != 0) continue;
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s/%s", g_lib_dirs[d], de->d_name);
            if (try_attach_library(full_path, bundle, num_cpus) == 1) {
                attached++;
            }
        }
        closedir(dir);
    }
    return attached;
}

static int scan_and_attach_proc_maps(uint32_t target_uid, bpf_bundle *bundle, int num_cpus) {
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    int attached = 0;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char status_path[128];
        snprintf(status_path, sizeof(status_path), "/proc/%s/status", de->d_name);
        FILE *sf = fopen(status_path, "r");
        if (!sf) continue;
        char line[512];
        uint32_t puid = 0;
        int found_uid = 0;
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                if (sscanf(line + 4, "%u", &puid) == 1) found_uid = 1;
                break;
            }
        }
        fclose(sf);
        if (!found_uid || puid != target_uid) continue;

        char maps_path[128];
        snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", de->d_name);
        FILE *mf = fopen(maps_path, "r");
        if (!mf) continue;
        while (fgets(line, sizeof(line), mf)) {
            char *slash = strchr(line, '/');
            if (!slash) continue;
            size_t slen = strlen(slash);
            while (slen > 0 && (slash[slen - 1] == '\n' || slash[slen - 1] == '\r' || slash[slen - 1] == ' ')) {
                slash[--slen] = '\0';
            }
            if (slen < 3 || strcmp(slash + slen - 3, ".so") != 0) continue;
            if (try_attach_library(slash, bundle, num_cpus) == 1) {
                attached++;
            }
        }
        fclose(mf);
    }
    closedir(proc);
    return attached;
}

static int scan_and_attach_defaults(bpf_bundle *bundle, int num_cpus) {
#if defined(__LP64__)
    const char *defaults[] = {
        "/apex/com.android.conscrypt/lib64/libssl.so",
        "/system/lib64/libssl.so",
        NULL
    };
#else
    const char *defaults[] = {
        "/apex/com.android.conscrypt/lib/libssl.so",
        "/system/lib/libssl.so",
        NULL
    };
#endif
    int attached = 0;
    for (int i = 0; defaults[i]; i++) {
        if (try_attach_library(defaults[i], bundle, num_cpus) == 1) {
            attached++;
        }
    }
    return attached;
}

typedef struct {
    uint32_t pid;
    uint32_t uid;
    uint64_t ssl_ptr;
    uint32_t direction;
    uint32_t length;
    uint64_t ts_ns;
} __attribute__((packed)) bpf_tls_hdr;

typedef struct {
    uint32_t magic;
    uint32_t pid;
    uint32_t uid;
    uint32_t direction;
    uint32_t length;
    uint64_t ssl_ptr;
} __attribute__((packed)) wire_tls_hdr;

typedef struct {
    int fd;
    void *base;
    size_t mmap_len;
    size_t data_size;
} perf_ring;

typedef struct {
    bpf_tls_hdr hdr;
    uint32_t payload_offset;
} batch_event_meta;

/* ================= JNI bridge: dynamic RegisterNatives interception ================= */

#define MAX_JNI_RULES 8
#define MAX_JNI_METHODS 8
#define MAX_JNI_TARGETS 32
#define JNI_ARRAY_BYTES_LIMIT (4U * 1024U * 1024U)

typedef struct {
    char lib_substr[128];
    char methods[MAX_JNI_METHODS][80];
    int method_count;
    int expect_json;
    int max_bytes;
    char magic[16];
    int magic_len;
} jni_hook_rule;

typedef struct {
    char lib_path[512];
    uint64_t addr;
    uint64_t file_offset;
    uint32_t method_id;
    int expect_json;
    int max_bytes;
    char magic[16];
    int magic_len;
    int perf_fd_count;
    int perf_fds[128];
} jni_target;

typedef struct {
    uint64_t name;
    uint64_t signature;
    uint64_t fn_ptr;
} jni_native_method;

static jni_hook_rule g_jni_rules[MAX_JNI_RULES];
static int g_jni_rule_count = 0;
static jni_target g_jni_targets[MAX_JNI_TARGETS];
static int g_jni_target_count = 0;
static int g_jni_attached_count = 0;
static int g_jni_hook_enabled = 0;
static char g_jni_libart_path[256] = {0};
static int g_jni_array_len_off = -1;
static int g_jni_array_data_off = -1;
static int g_jni_default_expect_json = 1;
static int g_jni_default_max_bytes = (int)JNI_ARRAY_BYTES_LIMIT;

static void handle_jni_event(const bpf_tls_hdr *bh, const uint8_t *extra);
static void attach_jni_register_probes(bpf_bundle *bundle, uint32_t target_uid, int num_cpus);

static batch_event_meta g_batch_metas[MAX_BATCH_EVENTS];
static uint8_t *g_batch_payload_pool = NULL;
static size_t g_batch_payload_pool_cap = 4 * 1024 * 1024;
static size_t g_batch_payload_pool_len = 0;
static int g_batch_count = 0;

static int compare_batch_events(const void *a, const void *b) {
    const batch_event_meta *ea = (const batch_event_meta *)a;
    const batch_event_meta *eb = (const batch_event_meta *)b;
    if (ea->hdr.ts_ns < eb->hdr.ts_ns) return -1;
    if (ea->hdr.ts_ns > eb->hdr.ts_ns) return 1;
    return 0;
}

static void flush_event_batch(void) {
    if (g_batch_count <= 0) return;
    if (g_batch_count > 1) {
        qsort(g_batch_metas, (size_t)g_batch_count, sizeof(batch_event_meta), compare_batch_events);
    }
    for (int i = 0; i < g_batch_count; i++) {
        wire_tls_hdr wh;
        wh.magic = 0x45554141U; // "AAUE" little-endian
        wh.pid = g_batch_metas[i].hdr.pid;
        wh.uid = g_batch_metas[i].hdr.uid;
        wh.direction = g_batch_metas[i].hdr.direction;
        wh.length = g_batch_metas[i].hdr.length;
        wh.ssl_ptr = g_batch_metas[i].hdr.ssl_ptr;
        fwrite(&wh, 1, sizeof(wh), stdout);
        if (wh.length > 0 && g_batch_payload_pool) {
            fwrite(g_batch_payload_pool + g_batch_metas[i].payload_offset, 1, wh.length, stdout);
        }
    }
    g_batch_count = 0;
    g_batch_payload_pool_len = 0;
}

static void drain_perf_ring(perf_ring *ring, size_t page_size, uint8_t *scratch, size_t scratch_cap) {
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)ring->base;
    uint8_t *data_base = (uint8_t *)ring->base + page_size;

    uint64_t data_head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    uint64_t data_tail = meta->data_tail;

    while (data_tail < data_head) {
        size_t off = (size_t)(data_tail & (ring->data_size - 1));
        struct perf_event_header phdr;
        size_t first = ring->data_size - off;
        if (first >= sizeof(phdr)) {
            memcpy(&phdr, data_base + off, sizeof(phdr));
        } else {
            memcpy(&phdr, data_base + off, first);
            memcpy((uint8_t *)&phdr + first, data_base, sizeof(phdr) - first);
        }

        if (phdr.size == 0 || phdr.size > ring->data_size) break;

        if (phdr.type == PERF_RECORD_SAMPLE && phdr.size <= scratch_cap) {
            size_t avail = ring->data_size - off;
            if (avail >= phdr.size) {
                memcpy(scratch, data_base + off, phdr.size);
            } else {
                memcpy(scratch, data_base + off, avail);
                memcpy(scratch + avail, data_base, phdr.size - avail);
            }

            if (phdr.size >= sizeof(struct perf_event_header) + sizeof(uint32_t) + sizeof(bpf_tls_hdr)) {
                uint32_t raw_size = 0;
                memcpy(&raw_size, scratch + sizeof(struct perf_event_header), sizeof(uint32_t));
                const uint8_t *sample = scratch + sizeof(struct perf_event_header) + sizeof(uint32_t);
                if (raw_size >= sizeof(bpf_tls_hdr) &&
                    sizeof(struct perf_event_header) + sizeof(uint32_t) + raw_size <= phdr.size) {
                    bpf_tls_hdr bh;
                    memcpy(&bh, sample, sizeof(bh));
                    if (bh.length > 0 && sizeof(bh) + bh.length <= raw_size) {
                        if (bh.direction >= 8U) {
                            flush_event_batch();
                            handle_jni_event(&bh, sample + sizeof(bh));
                        } else {
                        if (g_batch_count >= MAX_BATCH_EVENTS ||
                            g_batch_payload_pool_len + bh.length > g_batch_payload_pool_cap) {
                            flush_event_batch();
                        }
                        if (g_batch_payload_pool &&
                            g_batch_payload_pool_len + bh.length <= g_batch_payload_pool_cap) {
                            g_batch_metas[g_batch_count].hdr = bh;
                            g_batch_metas[g_batch_count].payload_offset = (uint32_t)g_batch_payload_pool_len;
                            memcpy(g_batch_payload_pool + g_batch_payload_pool_len, sample + sizeof(bh), bh.length);
                            g_batch_payload_pool_len += bh.length;
                            g_batch_count++;
                        }
                        }
                    }
                }
            }
        }
        data_tail += phdr.size;
    }

    __atomic_store_n(&meta->data_tail, data_tail, __ATOMIC_RELEASE);
}

/* ================= JNI bridge implementation ================= */

static bpf_bundle *g_jni_bundle = NULL;
static int g_jni_num_cpus = 0;

static int read_proc_mem(uint32_t pid, uint64_t addr, void *buf, size_t len) {
    if (!pid || !addr || !buf || !len) return -1;

    struct iovec local;
    struct iovec remote;
    local.iov_base = buf;
    local.iov_len = len;
    remote.iov_base = (void *)(uintptr_t)addr;
    remote.iov_len = len;
    if (process_vm_readv((pid_t)pid, &local, 1, &remote, 1, 0) == (ssize_t)len) {
        return 0;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/mem", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = pread(fd, buf, len, (off_t)addr);
    close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
}

// Resolve the load base of the first mapping whose path contains `substr`.
static int find_lib_mapping(
    uint32_t pid,
    const char *substr,
    char *path_out,
    size_t path_cap,
    uint64_t *base_out
) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;

    uint64_t best_base = 0;
    char best_path[512];
    best_path[0] = '\0';

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, substr)) continue;
        unsigned long long start = 0, end = 0, foff = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx", &start, &end, perms, &foff) != 4) continue;
        if (perms[0] != 'r') continue;
        char *slash = strchr(line, '/');
        if (!slash) continue;
        size_t slen = strlen(slash);
        while (slen > 0 && (slash[slen - 1] == '\n' || slash[slen - 1] == '\r' || slash[slen - 1] == ' ')) {
            slash[--slen] = '\0';
        }
        if (slen < 4) continue;
        uint64_t base = (uint64_t)start - (uint64_t)foff;
        if (best_base == 0 || base < best_base) {
            best_base = base;
            snprintf(best_path, sizeof(best_path), "%s", slash);
        }
    }
    fclose(f);

    if (best_base == 0) return -1;
    if (path_out && path_cap) snprintf(path_out, path_cap, "%s", best_path);
    if (base_out) *base_out = best_base;
    return 0;
}

// Look up a symbol in .symtab (not .dynsym) and translate its vaddr to a file offset.
// Used for libart.so, whose JNI entry points are not exported dynamically.
static int resolve_symtab_symbol_offset(
    const char *path,
    const char *needle,
    uint64_t *out_offset
) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    Elf64_Ehdr eh;
    if (fread(&eh, sizeof(eh), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_shnum == 0 || eh.e_shentsize != sizeof(Elf64_Shdr)) {
        fclose(f);
        return -1;
    }

    if (fseek(f, (long)eh.e_shoff, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    Elf64_Shdr *shdrs = (Elf64_Shdr *)calloc(eh.e_shnum, sizeof(Elf64_Shdr));
    if (!shdrs) {
        fclose(f);
        return -1;
    }
    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        free(shdrs);
        fclose(f);
        return -1;
    }

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;
    for (int i = 0; i < eh.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB && shdrs[i].sh_size > 0) {
            symtab = &shdrs[i];
            if (shdrs[i].sh_link < eh.e_shnum) strtab = &shdrs[shdrs[i].sh_link];
            break;
        }
    }
    if (!symtab || !strtab || strtab->sh_size < 2) {
        free(shdrs);
        fclose(f);
        return -1;
    }

    size_t sym_count = symtab->sh_size / sizeof(Elf64_Sym);
    Elf64_Sym *syms = (Elf64_Sym *)malloc(symtab->sh_size);
    char *strs = (char *)malloc(strtab->sh_size);
    if (!syms || !strs) {
        free(syms);
        free(strs);
        free(shdrs);
        fclose(f);
        return -1;
    }

    int io_ok = (fseek(f, (long)symtab->sh_offset, SEEK_SET) == 0 &&
                 fread(syms, 1, symtab->sh_size, f) == symtab->sh_size &&
                 fseek(f, (long)strtab->sh_offset, SEEK_SET) == 0 &&
                 fread(strs, 1, strtab->sh_size, f) == strtab->sh_size);

    int rc = -1;
    if (io_ok) {
        for (size_t i = 0; i < sym_count; i++) {
            if (syms[i].st_name == 0 || syms[i].st_name >= strtab->sh_size) continue;
            if (syms[i].st_value == 0 || syms[i].st_shndx == SHN_UNDEF) continue;
            const char *nm = strs + syms[i].st_name;
            if (!strstr(nm, needle)) continue;
            // Skip compiler-generated lambdas such as _ZZ...ENKUl...
            if (strncmp(nm, "_ZZ", 3) == 0) continue;

            for (int s = 0; s < eh.e_shnum; s++) {
                if (shdrs[s].sh_addr == 0 || shdrs[s].sh_size == 0) continue;
                if (shdrs[s].sh_type != SHT_PROGBITS) continue;
                if (syms[i].st_value < shdrs[s].sh_addr) continue;
                if (syms[i].st_value >= shdrs[s].sh_addr + shdrs[s].sh_size) continue;
                *out_offset = syms[i].st_value - shdrs[s].sh_addr + shdrs[s].sh_offset;
                rc = 0;
                break;
            }
            if (rc == 0) break;
        }
    }

    free(syms);
    free(strs);
    free(shdrs);
    fclose(f);
    return rc;
}

static int jni_addr_known(uint64_t addr) {
    for (int i = 0; i < g_jni_target_count; i++) {
        if (g_jni_targets[i].addr == addr) return 1;
    }
    return 0;
}

static int jni_attach_target(
    const char *lib_path,
    uint64_t addr,
    uint64_t file_offset,
    uint32_t method_id,
    int expect_json,
    int max_bytes,
    const char *magic,
    int magic_len
) {
    if (g_jni_target_count >= MAX_JNI_TARGETS || !g_jni_bundle) return -1;
    if (g_jni_bundle->prog_jni_arg_fd < 0 || g_jni_bundle->prog_jni_ret_fd < 0 ||
        g_jni_bundle->jni_addr_map_fd < 0) {
        return -1;
    }

    uint64_t key = addr;
    uint32_t value = method_id;
    union bpf_attr ma;
    memset(&ma, 0, sizeof(ma));
    ma.map_fd = (uint32_t)g_jni_bundle->jni_addr_map_fd;
    ma.key = (uint64_t)(uintptr_t)&key;
    ma.value = (uint64_t)(uintptr_t)&value;
    ma.flags = BPF_ANY;
    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &ma, sizeof(ma)) != 0) {
        fprintf(stderr, "WARN:jni_addr_map_update:errno=%d\n", errno);
        return -1;
    }

    jni_target *t = &g_jni_targets[g_jni_target_count];
    memset(t, 0, sizeof(*t));
    snprintf(t->lib_path, sizeof(t->lib_path), "%s", lib_path);
    t->addr = addr;
    t->file_offset = file_offset;
    t->method_id = method_id;
    t->expect_json = expect_json;
    t->max_bytes = max_bytes;
    t->magic_len = 0;
    if (magic && magic_len > 0 && magic_len < (int)sizeof(t->magic)) {
        memcpy(t->magic, magic, (size_t)magic_len);
        t->magic[magic_len] = '\0';
        t->magic_len = magic_len;
    }

    char suf_e[40];
    char suf_r[40];
    snprintf(suf_e, sizeof(suf_e), "jnie_%u", method_id);
    snprintf(suf_r, sizeof(suf_r), "jnir_%u", method_id);
    int fd_count = 0;
    if (attach_uprobe_pmu_or_tracefs(lib_path, file_offset, 0, suf_e,
                                     g_jni_bundle->prog_jni_arg_fd, g_jni_num_cpus,
                                     t->perf_fds, &fd_count) != 0) {
        fprintf(stderr, "WARN:jni_attach_entry_failed off=0x%llx\n", (unsigned long long)file_offset);
        return -1;
    }
    if (attach_uprobe_pmu_or_tracefs(lib_path, file_offset, 1, suf_r,
                                     g_jni_bundle->prog_jni_ret_fd, g_jni_num_cpus,
                                     t->perf_fds, &fd_count) != 0) {
        fprintf(stderr, "WARN:jni_attach_return_failed off=0x%llx\n", (unsigned long long)file_offset);
        return -1;
    }
    t->perf_fd_count = fd_count;
    g_jni_target_count++;
    g_jni_attached_count++;
    return 0;
}

static void jni_handle_register(uint32_t pid, uint64_t methods_ptr, uint32_t count) {
    if (!g_jni_hook_enabled || g_jni_rule_count == 0 || !g_jni_bundle) return;
    if (count == 0 || count > 512) return;

    // Reaching here proves the libart probe fires, even when no rule matches.
    fprintf(stderr, "INFO:jni_register_hit pid=%u count=%u\n", pid, count);
    fflush(stderr);

    size_t arr_bytes = sizeof(jni_native_method) * (size_t)count;
    if (arr_bytes > 131072U) return;

    jni_native_method *arr = (jni_native_method *)malloc(arr_bytes);
    if (!arr) return;
    if (read_proc_mem(pid, methods_ptr, arr, arr_bytes) != 0) {
        fprintf(stderr, "WARN:jni_read_methods:pid=%u\n", pid);
        free(arr);
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (arr[i].name == 0 || arr[i].fn_ptr == 0) continue;

        char nm[96];
        memset(nm, 0, sizeof(nm));
        if (read_proc_mem(pid, arr[i].name, nm, sizeof(nm) - 1) != 0) continue;
        nm[sizeof(nm) - 1] = '\0';
        if (nm[0] < 0x20 || nm[0] > 0x7E) continue;

        int rule_idx = -1;
        for (int r = 0; r < g_jni_rule_count && rule_idx < 0; r++) {
            for (int m = 0; m < g_jni_rules[r].method_count; m++) {
                if (strcmp(nm, g_jni_rules[r].methods[m]) == 0) {
                    rule_idx = r;
                    break;
                }
            }
        }
        if (rule_idx < 0) continue;
        if (jni_addr_known(arr[i].fn_ptr)) continue;
        if (g_jni_target_count >= MAX_JNI_TARGETS) break;

        char lib_path[512];
        memset(lib_path, 0, sizeof(lib_path));
        uint64_t base = 0;
        if (find_lib_mapping(pid, g_jni_rules[rule_idx].lib_substr,
                             lib_path, sizeof(lib_path), &base) != 0) {
            fprintf(stderr, "WARN:jni_lib_not_mapped:%s\n", g_jni_rules[rule_idx].lib_substr);
            continue;
        }
        if (arr[i].fn_ptr < base) continue;
        uint64_t off = arr[i].fn_ptr - base;
        if (off == 0 || off > 0x8000000ULL) continue;

        uint32_t method_id = (uint32_t)g_jni_target_count;
        if (jni_attach_target(lib_path, arr[i].fn_ptr, off, method_id,
                              g_jni_rules[rule_idx].expect_json,
                              g_jni_rules[rule_idx].max_bytes,
                              g_jni_rules[rule_idx].magic,
                              g_jni_rules[rule_idx].magic_len) == 0) {
            fprintf(stderr, "INFO:jni_hook lib=%s off=0x%llx id=%u method=%s\n",
                    lib_path, (unsigned long long)off, method_id, nm);
            fflush(stderr);
        }
    }

    free(arr);
}

// Last resort when the exact mirror::Array layout is unknown: scan the object head
// for a JSON payload and accept it only when the length prefix agrees and the
// payload closes with a matching bracket.
static int scan_json_array_window(
    uint32_t pid,
    uint64_t base,
    int max_bytes,
    uint8_t *out,
    size_t out_cap
) {
    uint8_t win[256];
    if (read_proc_mem(pid, base, win, sizeof(win)) != 0) return -1;

    uint32_t limit = (max_bytes > 0) ? (uint32_t)max_bytes : JNI_ARRAY_BYTES_LIMIT;

    for (int i = 8; i + 4 < (int)sizeof(win); i++) {
        if (win[i] != '{' && win[i] != '[') continue;
        uint32_t len = 0;
        memcpy(&len, win + i - 4, sizeof(len));
        if (len < 2 || len > limit) continue;
        if ((size_t)len > out_cap) continue;
        if (read_proc_mem(pid, base + (uint64_t)i, out, len) != 0) continue;
        uint8_t tail = out[len - 1];
        if (tail != '}' && tail != ']') continue;
        return (int)len;
    }
    return -1;
}

// ART hands out indirect JNI references: the jobject points at a slot holding the
// real mirror::Object*, sometimes with low tag bits set. Probe both the raw value
// and one level of dereference, and trust the payload shape to pick the winner.
// The decoder also builds binary arrays on the same thread, and a leading '{' alone
// is not proof of JSON (`{\x1d\x00\x00...` shows up in practice). Accept printable
// ASCII JSON and its UTF-16LE twin, which the parser transcodes later.
static int jni_json_head_ok(const uint8_t *b, uint32_t n) {
    if (n == 0) return 0;
    if (b[0] != '{' && b[0] != '[') return 0;
    if (n < 4) return 1;
    if (b[1] >= 0x20 && b[1] < 0x7F && b[2] >= 0x20 && b[2] < 0x7F) return 1;
    if (b[1] == 0 && b[3] == 0 && b[2] >= 0x20) return 1;
    return 0;
}

static int read_java_byte_array(
    uint32_t pid,
    uint64_t obj,
    int max_bytes,
    int expect_json,
    const char *magic,
    int magic_len,
    uint8_t *out,
    size_t out_cap
) {
    static const uint32_t layouts[][2] = {
        {8, 12}, {8, 16}, {16, 20}, {16, 24}, {12, 16}, {4, 8}
    };
    const size_t layout_count = sizeof(layouts) / sizeof(layouts[0]);

    uint64_t bases[2];
    int base_count = 0;
    bases[base_count++] = obj;

    uint64_t deref = 0;
    if (read_proc_mem(pid, obj, &deref, sizeof(deref)) == 0 && deref > 0x10000ULL) {
        uint64_t clean = deref & ~0x3ULL;
        if (clean != obj) {
            bases[base_count++] = clean;
        }
    }

    int fallback_valid = 0;
    uint32_t fallback_len = 0;
    uint64_t fallback_base = 0;
    size_t fallback_k = 0;

    for (int b = 0; b < base_count; b++) {
        for (size_t k = 0; k < layout_count; k++) {
            uint32_t len = 0;
            if (read_proc_mem(pid, bases[b] + layouts[k][0], &len, sizeof(len)) != 0) continue;
            if (len == 0 || len > JNI_ARRAY_BYTES_LIMIT) continue;
            if ((size_t)len > out_cap) continue;
            if (max_bytes > 0 && len > (uint32_t)max_bytes) continue;

            uint8_t head[16];
            memset(head, 0, sizeof(head));
            uint32_t probe = (len < sizeof(head)) ? len : (uint32_t)sizeof(head);
            if (read_proc_mem(pid, bases[b] + layouts[k][1], head, probe) != 0) continue;

            int head_json = (head[0] == '{' || head[0] == '[') ? 1 : 0;
            int head_magic = 0;
            if (!head_json && magic_len > 0 && probe >= (uint32_t)magic_len &&
                memcmp(head, magic, (size_t)magic_len) == 0) {
                head_magic = 1;
            }
            int shape_ok = head_json || head_magic;
            if (!shape_ok && !expect_json && head[0] >= 0x09 && head[0] < 0x7F) {
                shape_ok = 1;
            }

            if (!shape_ok) {
                if (!fallback_valid) {
                    fallback_valid = 1;
                    fallback_len = len;
                    fallback_base = bases[b];
                    fallback_k = k;
                }
                continue;
            }

            if (read_proc_mem(pid, bases[b] + layouts[k][1], out, len) != 0) continue;
            // A leading byte is not proof enough: a JSON payload must also close,
            // otherwise a mis-resolved object yields plausible-looking garbage.
            if (head_json && expect_json) {
                uint8_t tail = out[len - 1];
                if (tail != '}' && tail != ']' && tail != 0x00) continue;
            }
            if (g_jni_array_len_off != (int)layouts[k][0] || g_jni_array_data_off != (int)layouts[k][1]) {
                g_jni_array_len_off = (int)layouts[k][0];
                g_jni_array_data_off = (int)layouts[k][1];
                fprintf(stderr, "INFO:jni_array_layout len_off=%u data_off=%u deref=%d\n",
                        layouts[k][0], layouts[k][1], b);
                fflush(stderr);
            }
            return (int)len;
        }
    }

    if (expect_json) {
        for (int b = 0; b < base_count; b++) {
            int n = scan_json_array_window(pid, bases[b], max_bytes, out, out_cap);
            if (n > 0) {
                fprintf(stderr, "INFO:jni_array_window deref=%d len=%d\n", b, n);
                fflush(stderr);
                return n;
            }
        }
    }

    // Fallback only makes sense when the caller did not ask for JSON: with
    // expect_json the payload must be positively identified or dropped.
    if (!expect_json && fallback_valid) {
        if (read_proc_mem(pid, fallback_base + layouts[fallback_k][1], out, fallback_len) != 0) return -1;
        if (g_jni_array_len_off != (int)layouts[fallback_k][0]) {
            g_jni_array_len_off = (int)layouts[fallback_k][0];
            g_jni_array_data_off = (int)layouts[fallback_k][1];
            fprintf(stderr, "INFO:jni_array_layout len_off=%u data_off=%u (fallback)\n",
                    layouts[fallback_k][0], layouts[fallback_k][1]);
            fflush(stderr);
        }
        return (int)fallback_len;
    }
    return -1;
}

static void write_jni_result_frame(
    uint32_t pid,
    uint32_t uid,
    uint32_t method_id,
    const uint8_t *data,
    uint32_t len
) {
    wire_tls_hdr wh;
    memset(&wh, 0, sizeof(wh));
    wh.magic = 0x45554141U;
    wh.pid = pid;
    wh.uid = uid;
    wh.direction = 9U;
    wh.length = len;
    wh.ssl_ptr = (uint64_t)method_id;
    fwrite(&wh, 1, sizeof(wh), stdout);
    if (len > 0 && data) fwrite(data, 1, len, stdout);
    fflush(stdout);
}

// Decoders fill the result array with several SetByteArrayRegion() calls, so a
// single probe event can carry only a slice of the payload. Chunks are keyed by
// the array handle and stitched back together here.
#define MAX_REGION_ASSEMBLY 8
#define REGION_ASSEMBLY_MAX_BYTES (1024U * 1024U)
#define REGION_ASSEMBLY_TTL_MS 3000

typedef struct {
    int used;
    uint32_t pid;
    uint64_t key;
    uint32_t total;
    uint32_t filled;
    int64_t ts_ms;
    uint8_t *buf;
} region_assembly;

static region_assembly g_region_asm[MAX_REGION_ASSEMBLY];

static int64_t region_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void region_asm_release(region_assembly *a) {
    if (!a) return;
    if (a->buf) free(a->buf);
    memset(a, 0, sizeof(*a));
}

static region_assembly *region_asm_get(uint32_t pid, uint64_t key, uint32_t total) {
    region_assembly *reuse = NULL;
    int64_t now = region_now_ms();
    for (int i = 0; i < MAX_REGION_ASSEMBLY; i++) {
        region_assembly *a = &g_region_asm[i];
        if (!a->used) {
            if (!reuse) reuse = a;
            continue;
        }
        if (now - a->ts_ms > REGION_ASSEMBLY_TTL_MS) {
            region_asm_release(a);
            if (!reuse) reuse = a;
            continue;
        }
        if (a->pid == pid && a->key == key) {
            a->ts_ms = now;
            return a;
        }
    }
    if (!reuse) reuse = &g_region_asm[0];
    region_asm_release(reuse);

    reuse->buf = (uint8_t *)malloc(total);
    if (!reuse->buf) return NULL;
    reuse->used = 1;
    reuse->pid = pid;
    reuse->key = key;
    reuse->total = total;
    reuse->filled = 0;
    reuse->ts_ms = now;
    return reuse;
}

static void handle_jni_event(const bpf_tls_hdr *bh, const uint8_t *extra) {
    if (bh->direction == 8U && bh->length >= 8U) {
        uint32_t count = 0;
        memcpy(&count, extra + 4, sizeof(count));
        jni_handle_register(bh->pid, bh->ssl_ptr, count);
        return;
    }

    if (bh->direction == 11U && bh->length >= 24U) {
        // extra layout: method_id | start | chunk length | pad | array handle
        uint32_t method_id = 0;
        uint32_t start = 0;
        uint32_t chunk = 0;
        uint64_t key = 0;
        memcpy(&method_id, extra, sizeof(method_id));
        memcpy(&start, extra + 4, sizeof(start));
        memcpy(&chunk, extra + 8, sizeof(chunk));
        memcpy(&key, extra + 16, sizeof(key));
        if (method_id >= (uint32_t)g_jni_target_count) return;

        const jni_target *t = &g_jni_targets[method_id];
        if (chunk == 0 || chunk > JNI_ARRAY_BYTES_LIMIT || key == 0) return;

        // The array object is still alive *during* SetByteArrayRegion, so its length is
        // readable here even though the handle is dead once the decoder returns.
        uint32_t total = 0;
        uint64_t obj = key & ~0x3ULL;
        if (read_proc_mem(bh->pid, obj + 8, &total, sizeof(total)) != 0 ||
            total == 0 || total > JNI_ARRAY_BYTES_LIMIT || total < start + chunk) {
            total = start + chunk;
        }

        if (t->max_bytes > 0 && total > (uint32_t)t->max_bytes) return;

        if (total > REGION_ASSEMBLY_MAX_BYTES) {
            // Too big to stitch; only a single-call payload can still be trusted.
            if (start != 0 || chunk != total) return;
        }

        region_assembly *a = region_asm_get(bh->pid, key, total);
        if (!a) return;
        if ((uint64_t)start + chunk > a->total) {
            region_asm_release(a);
            return;
        }
        if (read_proc_mem(bh->pid, bh->ssl_ptr, a->buf + start, chunk) != 0) {
            region_asm_release(a);
            return;
        }
        if (start + chunk > a->filled) a->filled = start + chunk;
        if (a->filled < a->total) return;

        // Only a payload that starts at offset 0 can be shape-checked here, and only
        // such a payload is worth handing over: a mid-array slice is never valid JSON.
        int shaped = 1;
        if (t->expect_json) {
            shaped = jni_json_head_ok(a->buf, a->total);
            if (!shaped && t->magic_len > 0 && a->total >= (uint32_t)t->magic_len &&
                memcmp(a->buf, t->magic, (size_t)t->magic_len) == 0) {
                shaped = 1;
            }
        }

        static int region_seen = 0;
        if (region_seen < 10) {
            fprintf(stderr, "INFO:jni_region pid=%u mid=%u total=%u start=%u chunk=%u head=%02x%02x%02x%02x\n",
                    bh->pid, method_id, a->total, start, chunk,
                    a->buf[0], a->total > 1 ? a->buf[1] : 0,
                    a->total > 2 ? a->buf[2] : 0, a->total > 3 ? a->buf[3] : 0);
            fflush(stderr);
            region_seen++;
        }

        if (shaped) {
            write_jni_result_frame(bh->pid, bh->uid, method_id, a->buf, a->total);
        }
        region_asm_release(a);
        return;
    }

    if (bh->direction == 9U && bh->length >= 8U) {
        uint32_t method_id = 0;
        memcpy(&method_id, extra, sizeof(method_id));
        if (method_id >= (uint32_t)g_jni_target_count) return;

        static uint8_t *jni_buf = NULL;
        if (!jni_buf) {
            jni_buf = (uint8_t *)malloc(JNI_ARRAY_BYTES_LIMIT);
            if (!jni_buf) return;
        }

        const jni_target *t = &g_jni_targets[method_id];
        int n = read_java_byte_array(bh->pid, bh->ssl_ptr, t->max_bytes, t->expect_json,
                                     t->magic, t->magic_len,
                                     jni_buf, JNI_ARRAY_BYTES_LIMIT);
        // Best-effort only: see probe_array_region() for why the returned handle is
        // usually already poisoned. Kept because apps that return global refs still work.
        static int ret_seen = 0;
        if (ret_seen < 5) {
            fprintf(stderr, "INFO:jni_return_read pid=%u mid=%u n=%d\n", bh->pid, method_id, n);
            fflush(stderr);
            ret_seen++;
        }
        if (n <= 0) return;
        write_jni_result_frame(bh->pid, bh->uid, method_id, jni_buf, (uint32_t)n);
    }
}

static uint32_t find_pid_by_uid(uint32_t uid) {
    DIR *proc = opendir("/proc");
    if (!proc) return 0;
    uint32_t found = 0;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char status_path[128];
        snprintf(status_path, sizeof(status_path), "/proc/%s/status", de->d_name);
        FILE *sf = fopen(status_path, "r");
        if (!sf) continue;
        char line[512];
        uint32_t puid = 0;
        int got = 0;
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                if (sscanf(line + 4, "%u", &puid) == 1) got = 1;
                break;
            }
        }
        fclose(sf);
        if (!got || puid != uid) continue;
        found = (uint32_t)strtoul(de->d_name, NULL, 10);
        if (found) break;
    }
    closedir(proc);
    return found;
}

static int g_jni_reg_fds[2][128];
static int g_jni_reg_fd_count[2] = {0, 0};
static int g_jni_region_fds[128];
static int g_jni_region_fd_count = 0;

static void attach_jni_register_probes(bpf_bundle *bundle, uint32_t target_uid, int num_cpus) {
    if (!g_jni_hook_enabled || g_jni_rule_count == 0) return;
    if (bundle->prog_reg_natives_fd < 0 || bundle->prog_reg_natives_exit_fd < 0) {
        fprintf(stderr, "WARN:jni_register_prog_missing\n");
        return;
    }

    uint32_t pid = find_pid_by_uid(target_uid);
    char libart[256];
    libart[0] = '\0';
    if (pid) {
        find_lib_mapping(pid, "libart.so", libart, sizeof(libart), NULL);
    }
    if (!libart[0]) {
        const char *fallbacks[] = {
            "/apex/com.android.art/lib64/libart.so",
            "/system/lib64/libart.so"
        };
        for (size_t i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); i++) {
            if (file_exists_nonempty(fallbacks[i])) {
                snprintf(libart, sizeof(libart), "%s", fallbacks[i]);
                break;
            }
        }
    }
    if (!libart[0]) {
        fprintf(stderr, "WARN:jni_libart_not_found\n");
        return;
    }

    uint64_t offsets[2] = {0, 0};
    int off_count = 0;
    if (resolve_symtab_symbol_offset(libart, "3JNIILb0EE15RegisterNativesE", &offsets[off_count]) == 0) {
        off_count++;
    }
    if (resolve_symtab_symbol_offset(libart, "3JNIILb1EE15RegisterNativesE", &offsets[off_count]) == 0) {
        off_count++;
    }
    if (off_count == 0) {
        fprintf(stderr, "WARN:jni_register_natives_sym_not_found:%s\n", libart);
        return;
    }

    snprintf(g_jni_libart_path, sizeof(g_jni_libart_path), "%s", libart);

    int attached = 0;
    for (int i = 0; i < off_count; i++) {
        char suf_e[32];
        char suf_x[32];
        snprintf(suf_e, sizeof(suf_e), "jnireg_%de", i);
        snprintf(suf_x, sizeof(suf_x), "jnireg_%dx", i);

        if (attach_uprobe_pmu_or_tracefs(libart, offsets[i], 0, suf_e,
                                         bundle->prog_reg_natives_fd, num_cpus,
                                         g_jni_reg_fds[i], &g_jni_reg_fd_count[i]) != 0) {
            fprintf(stderr, "WARN:jni_reg_enter_attach_failed:idx=%d off=0x%llx\n",
                    i, (unsigned long long)offsets[i]);
            continue;
        }
        if (attach_uprobe_pmu_or_tracefs(libart, offsets[i], 1, suf_x,
                                         bundle->prog_reg_natives_exit_fd, num_cpus,
                                         g_jni_reg_fds[i], &g_jni_reg_fd_count[i]) != 0) {
            fprintf(stderr, "WARN:jni_reg_exit_attach_failed:idx=%d off=0x%llx\n",
                    i, (unsigned long long)offsets[i]);
            continue;
        }
        attached++;
        fprintf(stderr, "INFO:jni_register_probe lib=%s off=0x%llx variant=%d\n",
                libart, (unsigned long long)offsets[i], i);
        fflush(stderr);
    }

    if (attached == 0) {
        fprintf(stderr, "WARN:jni_register_probe_all_failed\n");
    }

    // Second observation point: the plaintext buffer handed to SetByteArrayRegion.
    // See probe_array_region() for why the returned handle cannot be used instead.
    if (bundle->prog_array_region_fd >= 0) {
        uint64_t region_off = 0;
        if (resolve_symtab_symbol_offset(libart, "3JNIILb0EE18SetByteArrayRegionE", &region_off) == 0) {
            if (attach_uprobe_pmu_or_tracefs(libart, region_off, 0, "jni_region",
                                             bundle->prog_array_region_fd, num_cpus,
                                             g_jni_region_fds, &g_jni_region_fd_count) == 0) {
                fprintf(stderr, "INFO:jni_region_probe lib=%s off=0x%llx\n",
                        libart, (unsigned long long)region_off);
                fflush(stderr);
            } else {
                fprintf(stderr, "WARN:jni_region_attach_failed off=0x%llx\n",
                        (unsigned long long)region_off);
            }
        } else {
            fprintf(stderr, "WARN:jni_region_sym_not_found:%s\n", libart);
        }
    }
}

static int is_system_lib_path(const char *path) {
    if (!path) return 0;
    return strncmp(path, "/system/", 8) == 0 ||
           strncmp(path, "/vendor/", 8) == 0 ||
           strncmp(path, "/apex/", 6) == 0 ||
           strncmp(path, "/system_ext/", 12) == 0 ||
           strncmp(path, "/product/", 9) == 0;
}

static const char *base_name_of(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void print_json_escaped(FILE *out, const char *s) {
    fputc('"', out);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            if (c == '\\') fputs("\\\\", out);
            else if (c == '"') fputs("\\\"", out);
            else if (c == '\n') fputs("\\n", out);
            else if (c == '\r') fputs("\\r", out);
            else if (c == '\t') fputs("\\t", out);
            else if (c < 0x20) fprintf(out, "\\u%04x", c);
            else fputc(c, out);
        }
    }
    fputc('"', out);
}

#define MAX_DISCOVER_SEEN 4096
#define MAX_DISCOVER_MATCHES 64
#define MAX_DISCOVER_UNMATCHED 64

typedef struct {
    dev_t dev;
    ino_t ino;
} discover_seen_id;

typedef struct {
    char path[512];
    dev_t dev;
    ino_t ino;
    int in_app_dir;
    library_probe_result probe;
} discover_item;

typedef struct {
    discover_seen_id *seen;
    int seen_count;
    discover_item *matches;
    int match_count;
    char unmatched[MAX_DISCOVER_UNMATCHED][128];
    int unmatched_count;
    int scanned_count;
} discover_state;

static void discover_add_unmatched_name(discover_state *ds, const char *name) {
    if (!ds || !name || !name[0]) return;
    for (int i = 0; i < ds->unmatched_count; i++) {
        if (strcmp(ds->unmatched[i], name) == 0) return;
    }
    if (ds->unmatched_count >= MAX_DISCOVER_UNMATCHED) return;
    snprintf(ds->unmatched[ds->unmatched_count++], sizeof(ds->unmatched[0]), "%s", name);
}

static void discover_record_library(
    discover_state *ds,
    const char *path,
    int in_app_dir
) {
    if (!ds || !path || !path[0] || !file_exists_nonempty(path)) return;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) return;

    for (int i = 0; i < ds->match_count; i++) {
        if ((ds->matches[i].dev == st.st_dev && ds->matches[i].ino == st.st_ino) ||
            strcmp(ds->matches[i].path, path) == 0) {
            if (in_app_dir && !ds->matches[i].in_app_dir) {
                ds->matches[i].in_app_dir = 1;
            }
            return;
        }
    }
    for (int i = 0; i < ds->seen_count; i++) {
        if (ds->seen[i].dev == st.st_dev && ds->seen[i].ino == st.st_ino) {
            return;
        }
    }
    if (ds->seen_count >= MAX_DISCOVER_SEEN) return;
    ds->seen[ds->seen_count].dev = st.st_dev;
    ds->seen[ds->seen_count].ino = st.st_ino;
    ds->seen_count++;

    ds->scanned_count++;
    library_probe_result probe;
    memset(&probe, 0, sizeof(probe));
    inspect_library_offsets(path, 1, &probe);

    if (probe.has_ssl || probe.has_cronet) {
        if (ds->match_count < MAX_DISCOVER_MATCHES) {
            discover_item *it = &ds->matches[ds->match_count++];
            memset(it, 0, sizeof(*it));
            snprintf(it->path, sizeof(it->path), "%s", path);
            it->dev = st.st_dev;
            it->ino = st.st_ino;
            it->in_app_dir = in_app_dir;
            it->probe = probe;
        }
    } else if (in_app_dir) {
        discover_add_unmatched_name(ds, base_name_of(path));
    }
}

static int run_discover_only(uint32_t target_uid, const char *explicit_lib) {
    discover_state ds;
    memset(&ds, 0, sizeof(ds));
    ds.seen = (discover_seen_id *)calloc(MAX_DISCOVER_SEEN, sizeof(discover_seen_id));
    ds.matches = (discover_item *)calloc(MAX_DISCOVER_MATCHES, sizeof(discover_item));
    if (!ds.seen || !ds.matches) {
        free(ds.seen);
        free(ds.matches);
        return 10;
    }

    if (explicit_lib && explicit_lib[0]) {
        discover_record_library(&ds, explicit_lib, !is_system_lib_path(explicit_lib));
    }

    for (int d = 0; d < g_lib_dir_count; d++) {
        DIR *dir = opendir(g_lib_dirs[d]);
        if (!dir) continue;
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] == '.') continue;
            size_t nlen = strlen(de->d_name);
            if (nlen < 3 || strcmp(de->d_name + nlen - 3, ".so") != 0) continue;
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s/%s", g_lib_dirs[d], de->d_name);
            discover_record_library(&ds, full_path, 1);
        }
        closedir(dir);
    }

    if (target_uid > 0) {
        DIR *proc = opendir("/proc");
        if (proc) {
            struct dirent *de;
            while ((de = readdir(proc)) != NULL) {
                if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
                char status_path[128];
                snprintf(status_path, sizeof(status_path), "/proc/%s/status", de->d_name);
                FILE *sf = fopen(status_path, "r");
                if (!sf) continue;
                char line[512];
                uint32_t puid = 0;
                int found_uid = 0;
                while (fgets(line, sizeof(line), sf)) {
                    if (strncmp(line, "Uid:", 4) == 0) {
                        if (sscanf(line + 4, "%u", &puid) == 1) found_uid = 1;
                        break;
                    }
                }
                fclose(sf);
                if (!found_uid || puid != target_uid) continue;

                char maps_path[128];
                snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", de->d_name);
                FILE *mf = fopen(maps_path, "r");
                if (!mf) continue;
                while (fgets(line, sizeof(line), mf)) {
                    char *slash = strchr(line, '/');
                    if (!slash) continue;
                    size_t slen = strlen(slash);
                    while (slen > 0 && (slash[slen - 1] == '\n' || slash[slen - 1] == '\r' || slash[slen - 1] == ' ')) {
                        slash[--slen] = '\0';
                    }
                    if (slen < 3 || strcmp(slash + slen - 3, ".so") != 0) continue;
                    if (strstr(slash, ".apk!/") != NULL && !is_system_lib_path(slash)) {
                        char apk_tag[128];
                        snprintf(apk_tag, sizeof(apk_tag), "%s (apk-mapped)", base_name_of(slash));
                        discover_add_unmatched_name(&ds, apk_tag);
                        continue;
                    }
                    discover_record_library(&ds, slash, !is_system_lib_path(slash));
                }
                fclose(mf);
            }
            closedir(proc);
        }
    }

#if defined(__LP64__)
    const char *defaults[] = {
        "/apex/com.android.conscrypt/lib64/libssl.so",
        "/system/lib64/libssl.so",
        NULL
    };
#else
    const char *defaults[] = {
        "/apex/com.android.conscrypt/lib/libssl.so",
        "/system/lib/libssl.so",
        NULL
    };
#endif
    for (int i = 0; defaults[i]; i++) {
        discover_record_library(&ds, defaults[i], 0);
    }

#if defined(__aarch64__)
    const char *arch = "arm64";
#elif defined(__arm__)
    const char *arch = "arm";
#elif defined(__x86_64__)
    const char *arch = "x86_64";
#else
    const char *arch = "x86";
#endif

    printf("{\n");
    printf("  \"uid\": %u,\n", target_uid);
    printf("  \"arch\": \"%s\",\n", arch);
    printf("  \"abi\": {\n");
    printf("    \"rawHeadersOffset\": \"0x%x\",\n", g_cronet_abi.raw_headers_offset);
    printf("    \"ioBufferDataOffset\": \"0x%x\",\n", g_cronet_abi.iobuf_data_offset);
    printf("    \"stringLayoutMode\": %u,\n", g_cronet_abi.string_layout_mode);
    printf("    \"vtableSlots\": [%d, %d, %d]\n", g_cronet_slot_hdr, g_cronet_slot_body, g_cronet_slot_fin);
    printf("  },\n");
    printf("  \"scannedLibrariesCount\": %d,\n", ds.scanned_count);
    printf("  \"libraries\": [\n");
    int first_lib = 1;
    for (int i = 0; i < ds.match_count; i++) {
        discover_item *it = &ds.matches[i];
        if (!it->probe.has_ssl && !it->probe.has_cronet) continue;
        if (!first_lib) printf(",\n");
        first_lib = 0;
        printf("    {\n");
        printf("      \"path\": "); print_json_escaped(stdout, it->path); printf(",\n");
        printf("      \"name\": "); print_json_escaped(stdout, base_name_of(it->path)); printf(",\n");
        printf("      \"inAppDir\": %s,\n", it->in_app_dir ? "true" : "false");
        printf("      \"sslSource\": "); print_json_escaped(stdout, it->probe.ssl_source); printf(",\n");
        printf("      \"sslWriteOffset\": \"0x%llx\",\n", (unsigned long long)it->probe.off_write);
        printf("      \"sslReadOffset\": \"0x%llx\",\n", (unsigned long long)it->probe.off_read);
        printf("      \"sslSniOffset\": \"0x%llx\",\n", (unsigned long long)it->probe.off_sni);
        printf("      \"cronetSource\": "); print_json_escaped(stdout, it->probe.cronet_source); printf(",\n");
        printf("      \"cronetCreateOffset\": \"0x%llx\",\n", (unsigned long long)it->probe.off_cr_req);
        printf("      \"cronetResponseStartedOffset\": \"0x%llx\",\n", (unsigned long long)it->probe.off_cr_hdr);
        printf("      \"cronetReadCompletedOffset\": \"0x%llx\",\n", (unsigned long long)it->probe.off_cr_body);
        printf("      \"cronetSucceededOffset\": \"0x%llx\"\n", (unsigned long long)it->probe.off_cr_fin);
        printf("    }");
    }
    printf("\n  ],\n");
    printf("  \"unmatchedAppLibs\": [\n");
    int limit_unmatched = ds.unmatched_count < 32 ? ds.unmatched_count : 32;
    for (int i = 0; i < limit_unmatched; i++) {
        if (i > 0) printf(",\n");
        printf("    ");
        print_json_escaped(stdout, ds.unmatched[i]);
    }
    printf("\n  ]\n");
    printf("}\n");
    fflush(stdout);
    free(ds.seen);
    free(ds.matches);
    return 0;
}

int main(int argc, char **argv) {
    uint32_t target_uid = 0;
    const char *explicit_lib = NULL;
    int discover_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--discover-only") == 0) {
            discover_only = 1;
        } else if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
            target_uid = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
            explicit_lib = argv[++i];
        } else if (strcmp(argv[i], "--lib-dir") == 0 && i + 1 < argc) {
            const char *ld = argv[++i];
            if (g_lib_dir_count < MAX_LIB_DIRS) {
                snprintf(g_lib_dirs[g_lib_dir_count++], sizeof(g_lib_dirs[0]), "%s", ld);
            }
        } else if (strcmp(argv[i], "--ssl-offsets") == 0 && i + 1 < argc) {
            const char *spec = argv[++i];
            if (g_ssl_rule_count < MAX_OFFSET_RULES) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s", spec);
                char *p1 = strchr(buf, ':');
                char *p2 = p1 ? strchr(p1 + 1, ':') : NULL;
                char *p3 = p2 ? strchr(p2 + 1, ':') : NULL;
                if (p1 && p2) {
                    *p1 = '\0';
                    *p2 = '\0';
                    if (p3) *p3 = '\0';
                    ssl_offset_rule *r = &g_ssl_rules[g_ssl_rule_count];
                    snprintf(r->lib_substr, sizeof(r->lib_substr), "%s", buf);
                    r->write_off = (uint64_t)strtoull(p1 + 1, NULL, 0);
                    r->read_off = (uint64_t)strtoull(p2 + 1, NULL, 0);
                    r->sni_off = p3 ? (uint64_t)strtoull(p3 + 1, NULL, 0) : 0ULL;
                    if (r->lib_substr[0] && r->write_off > 0 && r->read_off > 0) {
                        g_ssl_rule_count++;
                    }
                }
            }
        } else if (strcmp(argv[i], "--cronet-offsets") == 0 && i + 1 < argc) {
            const char *spec = argv[++i];
            if (g_cronet_rule_count < MAX_OFFSET_RULES) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s", spec);
                char *p1 = strchr(buf, ':');
                char *p2 = p1 ? strchr(p1 + 1, ':') : NULL;
                char *p3 = p2 ? strchr(p2 + 1, ':') : NULL;
                char *p4 = p3 ? strchr(p3 + 1, ':') : NULL;
                if (p1 && p2 && p3 && p4) {
                    *p1 = '\0'; *p2 = '\0'; *p3 = '\0'; *p4 = '\0';
                    cronet_offset_rule *r = &g_cronet_rules[g_cronet_rule_count];
                    snprintf(r->lib_substr, sizeof(r->lib_substr), "%s", buf);
                    r->create_off = (uint64_t)strtoull(p1 + 1, NULL, 0);
                    r->hdr_off = (uint64_t)strtoull(p2 + 1, NULL, 0);
                    r->body_off = (uint64_t)strtoull(p3 + 1, NULL, 0);
                    r->fin_off = (uint64_t)strtoull(p4 + 1, NULL, 0);
                    if (r->lib_substr[0] && r->create_off > 0 && r->hdr_off > 0 && r->body_off > 0 && r->fin_off > 0) {
                        g_cronet_rule_count++;
                    }
                }
            }
        } else if (strcmp(argv[i], "--cronet-sig") == 0 && i + 1 < argc) {
            const char *sig = argv[++i];
            if (g_custom_cronet_sig_count < MAX_CRONET_SIGS && sig[0]) {
                snprintf(g_custom_cronet_sigs[g_custom_cronet_sig_count++], sizeof(g_custom_cronet_sigs[0]), "%s", sig);
            }
        } else if (strcmp(argv[i], "--cronet-slots") == 0 && i + 1 < argc) {
            int s_hdr = 3, s_body = 4, s_fin = 5;
            if (sscanf(argv[++i], "%d,%d,%d", &s_hdr, &s_body, &s_fin) == 3 &&
                s_hdr >= 0 && s_body >= 0 && s_fin >= 0 &&
                s_hdr < 16 && s_body < 16 && s_fin < 16) {
                g_cronet_slot_hdr = s_hdr;
                g_cronet_slot_body = s_body;
                g_cronet_slot_fin = s_fin;
            }
        } else if (strcmp(argv[i], "--cronet-abi") == 0 && i + 1 < argc) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s", argv[++i]);
            char *c1 = strchr(buf, ',');
            char *c2 = c1 ? strchr(c1 + 1, ',') : NULL;
            if (c1 && c2) {
                *c1 = '\0';
                *c2 = '\0';
                uint32_t hdr_o = (uint32_t)strtoul(buf, NULL, 0);
                uint32_t iob_o = (uint32_t)strtoul(c1 + 1, NULL, 0);
                uint32_t mode = (uint32_t)strtoul(c2 + 1, NULL, 0);
                if (hdr_o > 0 && hdr_o <= 256U) g_cronet_abi.raw_headers_offset = hdr_o;
                if (iob_o > 0 && iob_o <= 256U) g_cronet_abi.iobuf_data_offset = iob_o;
                g_cronet_abi.string_layout_mode = mode;
            }
        } else if (strcmp(argv[i], "--jni-hook") == 0 && i + 1 < argc) {
            const char *spec = argv[++i];
            if (g_jni_rule_count < MAX_JNI_RULES) {
                char buf[1024];
                snprintf(buf, sizeof(buf), "%s", spec);
                char *colon = strchr(buf, ':');
                if (colon) {
                    *colon = '\0';
                    jni_hook_rule *r = &g_jni_rules[g_jni_rule_count];
                    memset(r, 0, sizeof(*r));
                    snprintf(r->lib_substr, sizeof(r->lib_substr), "%s", buf);
                    r->expect_json = g_jni_default_expect_json;
                    r->max_bytes = g_jni_default_max_bytes;

                    char *p = colon + 1;
                    while (p && *p && r->method_count < MAX_JNI_METHODS) {
                        char *comma = strchr(p, ',');
                        if (comma) *comma = '\0';
                        if (*p) {
                            snprintf(r->methods[r->method_count],
                                     sizeof(r->methods[0]), "%s", p);
                            r->method_count++;
                        }
                        p = comma ? comma + 1 : NULL;
                    }
                    if (r->lib_substr[0] && r->method_count > 0) {
                        g_jni_rule_count++;
                        g_jni_hook_enabled = 1;
                    }
                }
            }
        } else if (strcmp(argv[i], "--jni-no-json") == 0) {
            g_jni_default_expect_json = 0;
        } else if (strcmp(argv[i], "--jni-max-bytes") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v > 0 && v <= (long)JNI_ARRAY_BYTES_LIMIT) {
                g_jni_default_max_bytes = (int)v;
            }
        } else if (strcmp(argv[i], "--jni-magic") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (g_jni_rule_count > 0 && m[0]) {
                jni_hook_rule *r = &g_jni_rules[g_jni_rule_count - 1];
                size_t ml = strlen(m);
                if (ml < sizeof(r->magic)) {
                    memcpy(r->magic, m, ml);
                    r->magic[ml] = '\0';
                    r->magic_len = (int)ml;
                }
            }
        }
    }

    if (discover_only) {
        if (target_uid == 0 && g_lib_dir_count == 0 && (!explicit_lib || !explicit_lib[0])) {
            fprintf(stderr, "ERR:usage:--uid, --lib-dir, or --lib required with --discover-only\n");
            return 2;
        }
        return run_discover_only(target_uid, explicit_lib);
    }

    if (target_uid == 0) {
        fprintf(stderr, "ERR:usage:--uid <uid> required\n");
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, on_signal);
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    raise_memlock_rlimit();

    snprintf(g_probe_prefix, sizeof(g_probe_prefix), "aau_%d", getpid());

    int num_cpus = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (num_cpus <= 0) num_cpus = 1;
    if (num_cpus > 128) num_cpus = 128;

    bpf_bundle bundle;
    if (load_bpf_object(g_aau_ebpf_bpf_o, g_aau_ebpf_bpf_o_len, num_cpus, &bundle) != 0) {
        return 5;
    }

    // Write target UID into target_uid_map[0]
    uint32_t zero = 0;
    union bpf_attr uattr;
    memset(&uattr, 0, sizeof(uattr));
    uattr.map_fd = (uint32_t)bundle.target_uid_map_fd;
    uattr.key = (uint64_t)(uintptr_t)&zero;
    uattr.value = (uint64_t)(uintptr_t)&target_uid;
    uattr.flags = BPF_ANY;
    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &uattr, sizeof(uattr)) != 0) {
        fprintf(stderr, "ERR:map_update_uid:errno=%d\n", errno);
        return 6;
    }

    if (bundle.cronet_abi_map_fd >= 0) {
        union bpf_attr aattr;
        memset(&aattr, 0, sizeof(aattr));
        aattr.map_fd = (uint32_t)bundle.cronet_abi_map_fd;
        aattr.key = (uint64_t)(uintptr_t)&zero;
        aattr.value = (uint64_t)(uintptr_t)&g_cronet_abi;
        aattr.flags = BPF_ANY;
        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &aattr, sizeof(aattr)) != 0) {
            fprintf(stderr, "WARN:map_update_cronet_abi:errno=%d\n", errno);
        }
    }

    // Setup per-CPU perf ring buffers
    long page_size_l = sysconf(_SC_PAGESIZE);
    size_t page_size = (page_size_l > 0) ? (size_t)page_size_l : 4096U;
    size_t ring_pages = 16; // Power of 2 (64KB per CPU)
    size_t mmap_len = (1 + ring_pages) * page_size;

    perf_ring *rings = (perf_ring *)calloc((size_t)num_cpus, sizeof(perf_ring));
    struct pollfd *pfds = (struct pollfd *)calloc((size_t)num_cpus + 1, sizeof(struct pollfd));

    int active_rings = 0;
    int last_ring_errno = 0;
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        rings[cpu].fd = -1;
        pfds[cpu].fd = -1;

        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_SOFTWARE;
        attr.size = sizeof(attr);
        attr.config = PERF_COUNT_SW_BPF_OUTPUT;
        attr.sample_type = PERF_SAMPLE_RAW;
        attr.wakeup_events = 1;

        int pfd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pfd < 0) {
            last_ring_errno = errno;
            continue;
        }
        void *mapped = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
        if (mapped == MAP_FAILED) {
            fprintf(stderr, "ERR:perf_ring_mmap(cpu=%d):errno=%d(%s)\n", cpu, errno, strerror(errno));
            close(pfd);
            return 8;
        }
        ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);

        uint32_t cpu_key = (uint32_t)cpu;
        uint32_t fd_val = (uint32_t)pfd;
        union bpf_attr eattr;
        memset(&eattr, 0, sizeof(eattr));
        eattr.map_fd = (uint32_t)bundle.events_map_fd;
        eattr.key = (uint64_t)(uintptr_t)&cpu_key;
        eattr.value = (uint64_t)(uintptr_t)&fd_val;
        eattr.flags = BPF_ANY;
        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &eattr, sizeof(eattr)) != 0) {
            fprintf(stderr, "ERR:events_map_update(cpu=%d):errno=%d\n", cpu, errno);
            munmap(mapped, mmap_len);
            close(pfd);
            return 9;
        }

        rings[cpu].fd = pfd;
        rings[cpu].base = mapped;
        rings[cpu].mmap_len = mmap_len;
        rings[cpu].data_size = ring_pages * page_size;
        pfds[cpu].fd = pfd;
        pfds[cpu].events = POLLIN;
        active_rings++;
    }
    if (active_rings == 0) {
        fprintf(stderr, "ERR:perf_ring_open:errno=%d(%s)\n", last_ring_errno, strerror(last_ring_errno));
        return 7;
    }

    pfds[num_cpus].fd = STDIN_FILENO;
    pfds[num_cpus].events = POLLHUP | POLLERR;

    g_jni_bundle = &bundle;
    g_jni_num_cpus = (num_cpus > 128) ? 128 : num_cpus;
    attach_jni_register_probes(&bundle, target_uid, g_jni_num_cpus);

    if (explicit_lib && explicit_lib[0]) {
        try_attach_library(explicit_lib, &bundle, num_cpus);
    }
    scan_and_attach_lib_dirs(&bundle, num_cpus);
    scan_and_attach_proc_maps(target_uid, &bundle, num_cpus);
    scan_and_attach_defaults(&bundle, num_cpus);

    if (g_attached_lib_count == 0 && !g_jni_hook_enabled) {
        fprintf(stderr, "ERR:libssl_not_found:%s\n", g_last_attach_err[0] ? g_last_attach_err : "none");
        return 3;
    }

    // Signal readiness to Java parent
    fprintf(stderr, "READY:%s\n",
            g_attached_lib_count > 0 ? g_attached_libs[0].path
                                     : (g_jni_hook_enabled ? "jni-bridge" : "none"));
    fflush(stderr);

    g_batch_payload_pool = (uint8_t *)malloc(g_batch_payload_pool_cap);
    size_t scratch_cap = 65536;
    uint8_t *scratch = (uint8_t *)malloc(scratch_cap);
    time_t last_rescan = time(NULL);

    while (!g_stop) {
        int pr = poll(pfds, (nfds_t)(num_cpus + 1), 250);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfds[num_cpus].revents & (POLLHUP | POLLERR)) {
            break;
        }
        int had_data = 0;
        for (int cpu = 0; cpu < num_cpus; cpu++) {
            if (rings[cpu].fd >= 0 && (pfds[cpu].revents & POLLIN)) {
                drain_perf_ring(&rings[cpu], page_size, scratch, scratch_cap);
                had_data = 1;
            }
        }
        if (had_data) {
            flush_event_batch();
            fflush(stdout);
        }

        // Periodic hot-rescan of /proc/<pid>/maps every 2 seconds for lazy dlopen
        time_t now = time(NULL);
        if (now - last_rescan >= 2) {
            last_rescan = now;
            scan_and_attach_proc_maps(target_uid, &bundle, num_cpus);
        }
    }

    for (int i = 0; i < g_attached_lib_count; i++) {
        for (int k = 0; k < g_attached_libs[i].uprobe_fd_count; k++) {
            close(g_attached_libs[i].uprobe_fds[k]);
        }
        g_attached_libs[i].uprobe_fd_count = 0;
    }
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        if (rings[cpu].fd >= 0) {
            munmap(rings[cpu].base, rings[cpu].mmap_len);
            close(rings[cpu].fd);
        }
    }
    cleanup_tracefs_uprobes();
    free(scratch);
    if (g_batch_payload_pool) {
        free(g_batch_payload_pool);
        g_batch_payload_pool = NULL;
    }
    free(pfds);
    free(rings);
    return 0;
}
