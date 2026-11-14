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
        "uprobe/cronet_succeeded"
    };
    int *prog_fds[] = {
        &out->prog_write_fd,
        &out->prog_read_enter_fd,
        &out->prog_read_exit_fd,
        &out->prog_sni_fd,
        &out->prog_cronet_create_fd,
        &out->prog_cronet_resp_started_fd,
        &out->prog_cronet_read_completed_fd,
        &out->prog_cronet_succeeded_fd
    };
    const int prog_required[] = {1, 1, 1, 0, 0, 0, 0, 0};

    for (int p = 0; p < 8; p++) {
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

    uint64_t off_write = 0, off_read = 0, off_sni = 0;
    int has_ssl = 0;
    for (int r = 0; r < g_ssl_rule_count; r++) {
        if (strstr(path, g_ssl_rules[r].lib_substr) != NULL &&
            g_ssl_rules[r].write_off != 0 && g_ssl_rules[r].read_off != 0) {
            off_write = g_ssl_rules[r].write_off;
            off_read = g_ssl_rules[r].read_off;
            off_sni = g_ssl_rules[r].sni_off;
            has_ssl = 1;
            break;
        }
    }
    if (!has_ssl) {
        if (resolve_elf_symbol_offset(path, "SSL_write", &off_write) == 0 &&
            resolve_elf_symbol_offset(path, "SSL_read", &off_read) == 0) {
            has_ssl = 1;
            resolve_elf_symbol_offset(path, "SSL_set_tlsext_host_name", &off_sni);
        }
#if defined(__LP64__) && defined(__aarch64__)
        else if (resolve_stripped_boringssl_offsets(path, &off_write, &off_read, &off_sni) == 0) {
            has_ssl = 1;
        }
#endif
    }

#if defined(__LP64__) && defined(__aarch64__)
    uint64_t off_cr_req = 0, off_cr_hdr = 0, off_cr_body = 0, off_cr_fin = 0;
    int cronet_progs_ready = (
        bundle->prog_cronet_create_fd >= 0 &&
        bundle->prog_cronet_resp_started_fd >= 0 &&
        bundle->prog_cronet_read_completed_fd >= 0 &&
        bundle->prog_cronet_succeeded_fd >= 0
    );
    int has_cronet = 0;
    if (cronet_progs_ready) {
        for (int r = 0; r < g_cronet_rule_count; r++) {
            if (strstr(path, g_cronet_rules[r].lib_substr) != NULL &&
                g_cronet_rules[r].create_off != 0 && g_cronet_rules[r].hdr_off != 0 &&
                g_cronet_rules[r].body_off != 0 && g_cronet_rules[r].fin_off != 0) {
                off_cr_req = g_cronet_rules[r].create_off;
                off_cr_hdr = g_cronet_rules[r].hdr_off;
                off_cr_body = g_cronet_rules[r].body_off;
                off_cr_fin = g_cronet_rules[r].fin_off;
                has_cronet = 1;
                break;
            }
        }
        if (!has_cronet &&
            resolve_cronet_offsets(path, &off_cr_req, &off_cr_hdr, &off_cr_body, &off_cr_fin) == 0) {
            has_cronet = 1;
        }
    }
#else
    int has_cronet = 0;
#endif

    if (!has_ssl && !has_cronet) {
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
        data_tail += phdr.size;
    }

    __atomic_store_n(&meta->data_tail, data_tail, __ATOMIC_RELEASE);
}

int main(int argc, char **argv) {
    uint32_t target_uid = 0;
    const char *explicit_lib = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
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
        }
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

    if (explicit_lib && explicit_lib[0]) {
        try_attach_library(explicit_lib, &bundle, num_cpus);
    }
    scan_and_attach_lib_dirs(&bundle, num_cpus);
    scan_and_attach_proc_maps(target_uid, &bundle, num_cpus);
    scan_and_attach_defaults(&bundle, num_cpus);

    if (g_attached_lib_count == 0) {
        fprintf(stderr, "ERR:libssl_not_found:%s\n", g_last_attach_err[0] ? g_last_attach_err : "none");
        return 3;
    }

    // Signal readiness to Java parent
    fprintf(stderr, "READY:%s\n", g_attached_libs[0].path);
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
