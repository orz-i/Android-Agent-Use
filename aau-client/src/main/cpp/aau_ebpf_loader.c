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

static volatile sig_atomic_t g_stop = 0;
static char g_tracefs_dir[256] = {0};
static char g_probe_prefix[64] = {0};
static char g_lib_dirs[MAX_LIB_DIRS][512];
static int g_lib_dir_count = 0;

typedef struct {
    char path[512];
    dev_t dev;
    ino_t ino;
    uint64_t off_write;
    uint64_t off_read;
    int uprobe_fd_count;
    int uprobe_fds[3 * 128];
} attached_lib;

static attached_lib g_attached_libs[MAX_ATTACHED_LIBS];
static int g_attached_lib_count = 0;

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
                            vaddr >= phdrs[p].p_vaddr &&
                            vaddr < phdrs[p].p_vaddr + phdrs[p].p_memsz) {
                            *out_offset = (vaddr - phdrs[p].p_vaddr) + phdrs[p].p_offset;
                            rc = 0;
                            break;
                        }
                    }
                    if (rc != 0) {
                        *out_offset = vaddr;
                        rc = 0;
                    }
                    break;
                }
            }
        }
    } else if (ident[EI_CLASS] == ELFCLASS32) {
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

                    uint64_t vaddr = syms[s].st_value;
                    for (int p = 0; p < eh->e_phnum; p++) {
                        if (phdrs[p].p_type == PT_LOAD &&
                            vaddr >= phdrs[p].p_vaddr &&
                            vaddr < phdrs[p].p_vaddr + phdrs[p].p_memsz) {
                            *out_offset = (vaddr - phdrs[p].p_vaddr) + phdrs[p].p_offset;
                            rc = 0;
                            break;
                        }
                    }
                    if (rc != 0) {
                        *out_offset = vaddr;
                        rc = 0;
                    }
                    break;
                }
            }
        }
    }

    munmap(base, map_size);
    return rc;
}



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
    int prog_write_fd;
    int prog_read_enter_fd;
    int prog_read_exit_fd;
} bpf_bundle;

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
        map_count++;
    }

    uint32_t kver = detect_kernel_version_code();
    const char *prog_secs[] = {"uprobe/ssl_write", "uprobe/ssl_read_enter", "uretprobe/ssl_read_exit"};
    int *prog_fds[] = {&out->prog_write_fd, &out->prog_read_enter_fd, &out->prog_read_exit_fd};

    for (int p = 0; p < 3; p++) {
        int sec_idx = -1;
        for (int i = 0; i < eh->e_shnum; i++) {
            if (strcmp(shstrtab + shdrs[i].sh_name, prog_secs[p]) == 0) {
                sec_idx = i;
                break;
            }
        }
        if (sec_idx < 0 || shdrs[sec_idx].sh_size == 0) {
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

        char log_buf[16384];
        memset(log_buf, 0, sizeof(log_buf));
        union bpf_attr pattr;
        memset(&pattr, 0, sizeof(pattr));
        pattr.prog_type = BPF_PROG_TYPE_KPROBE;
        pattr.insn_cnt = (uint32_t)insn_count;
        pattr.insns = (uint64_t)(uintptr_t)insns;
        pattr.license = (uint64_t)(uintptr_t)"GPL";
        pattr.kern_version = kver;
        pattr.log_level = 1;
        pattr.log_size = sizeof(log_buf);
        pattr.log_buf = (uint64_t)(uintptr_t)log_buf;

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
                memset(log_buf, 0, sizeof(log_buf));
                pfd = sys_bpf(BPF_PROG_LOAD, &pattr, sizeof(pattr));
            }
        }

        free(insns);
        if (pfd < 0) {
            fprintf(stderr, "ERR:bpf_prog_load(%s):errno=%d(%s):%s\n",
                    prog_secs[p], errno, strerror(errno), log_buf);
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

static void cleanup_tracefs_uprobes(void) {
    if (!g_tracefs_dir[0] || !g_probe_prefix[0]) return;
    char events_path[300];
    snprintf(events_path, sizeof(events_path), "%s/uprobe_events", g_tracefs_dir);
    int fd = open(events_path, O_WRONLY | O_APPEND);
    if (fd >= 0) {
        char cmd[256];
        int n = snprintf(cmd, sizeof(cmd), "-:uprobes/%s_w\n-:uprobes/%s_rw\n-:uprobes/%s_rr\n",
                         g_probe_prefix, g_probe_prefix, g_probe_prefix);
        if (n > 0) write(fd, cmd, (size_t)n);

        for (int i = 0; i < g_attached_lib_count && i < MAX_ATTACHED_LIBS; i++) {
            n = snprintf(cmd, sizeof(cmd), "-:uprobes/%s_w_%d\n-:uprobes/%s_rw_%d\n-:uprobes/%s_rr_%d\n",
                         g_probe_prefix, i, g_probe_prefix, i, g_probe_prefix, i);
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
                for (int k = 0; k < opened; k++) close(perf_fds[*perf_fd_count + k]);
                opened = -1;
                break;
            }
            if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0 ||
                ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
                close(pfd);
                for (int k = 0; k < opened; k++) close(perf_fds[*perf_fd_count + k]);
                opened = -1;
                break;
            }
            perf_fds[*perf_fd_count + opened] = pfd;
            opened++;
        }
        if (opened > 0) {
            *perf_fd_count += opened;
            return 0;
        }
    }

    // Method 2: Tracefs uprobe_events fallback
    const char *tracefs = find_tracefs_dir();
    if (!tracefs) {
        fprintf(stderr, "ERR:no_uprobe_pmu_or_tracefs\n");
        return -1;
    }
    snprintf(g_tracefs_dir, sizeof(g_tracefs_dir), "%s", tracefs);

    char uprobe_events_path[300];
    snprintf(uprobe_events_path, sizeof(uprobe_events_path), "%s/uprobe_events", tracefs);
    int ufd = open(uprobe_events_path, O_WRONLY | O_APPEND);
    if (ufd < 0) {
        fprintf(stderr, "ERR:open_uprobe_events:errno=%d(%s)\n", errno, strerror(errno));
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
        fprintf(stderr, "ERR:write_uprobe_events:errno=%d(%s)\n", werrno, strerror(werrno));
        return -1;
    }

    char id_path[384];
    snprintf(id_path, sizeof(id_path), "%s/events/uprobes/%s_%s/id", tracefs, g_probe_prefix, probe_suffix);
    int tp_id = -1;
    if (read_int_file(id_path, &tp_id) != 0 || tp_id <= 0) {
        fprintf(stderr, "ERR:read_tracepoint_id(%s)\n", id_path);
        return -1;
    }

    int opened = 0;
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_TRACEPOINT;
        attr.size = sizeof(attr);
        attr.config = (uint64_t)tp_id;

        int pfd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pfd < 0) {
            for (int k = 0; k < opened; k++) close(perf_fds[*perf_fd_count + k]);
            fprintf(stderr, "ERR:perf_event_open_tp:errno=%d(%s)\n", errno, strerror(errno));
            return -1;
        }
        if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0 ||
            ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
            int ioerr = errno;
            close(pfd);
            for (int k = 0; k < opened; k++) close(perf_fds[*perf_fd_count + k]);
            fprintf(stderr, "ERR:ioc_set_bpf:errno=%d(%s)\n", ioerr, strerror(ioerr));
            return -1;
        }
        perf_fds[*perf_fd_count + opened] = pfd;
        opened++;
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

    uint64_t off_write = 0, off_read = 0;
    if (resolve_elf_symbol_offset(path, "SSL_write", &off_write) != 0 ||
        resolve_elf_symbol_offset(path, "SSL_read", &off_read) != 0) {
        return -1;
    }

    int idx = g_attached_lib_count;
    char suf_w[32], suf_rw[32], suf_rr[32];
    snprintf(suf_w, sizeof(suf_w), "w_%d", idx);
    snprintf(suf_rw, sizeof(suf_rw), "rw_%d", idx);
    snprintf(suf_rr, sizeof(suf_rr), "rr_%d", idx);

    int fd_cnt = 0;
    int rc1 = attach_uprobe_pmu_or_tracefs(path, off_write, 0, suf_w, bundle->prog_write_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt);
    int rc2 = attach_uprobe_pmu_or_tracefs(path, off_read, 0, suf_rw, bundle->prog_read_enter_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt);
    int rc3 = attach_uprobe_pmu_or_tracefs(path, off_read, 1, suf_rr, bundle->prog_read_exit_fd, num_cpus, g_attached_libs[idx].uprobe_fds, &fd_cnt);

    if (rc1 != 0 || rc2 != 0 || rc3 != 0) {
        for (int k = 0; k < fd_cnt; k++) {
            close(g_attached_libs[idx].uprobe_fds[k]);
        }
        return -1;
    }

    snprintf(g_attached_libs[idx].path, sizeof(g_attached_libs[idx].path), "%s", path);
    g_attached_libs[idx].dev = st.st_dev;
    g_attached_libs[idx].ino = st.st_ino;
    g_attached_libs[idx].off_write = off_write;
    g_attached_libs[idx].off_read = off_read;
    g_attached_libs[idx].uprobe_fd_count = fd_cnt;
    g_attached_lib_count++;

    fprintf(stderr, "ATTACHED:%s\n", path);
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
        "/apex/com.android.conscrypt/lib/libssl.so",
        "/system/lib/libssl.so",
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

    // Setup per-CPU perf ring buffers
    long page_size_l = sysconf(_SC_PAGESIZE);
    size_t page_size = (page_size_l > 0) ? (size_t)page_size_l : 4096U;
    size_t ring_pages = 16; // Power of 2 (64KB per CPU)
    size_t mmap_len = (1 + ring_pages) * page_size;

    perf_ring *rings = (perf_ring *)calloc((size_t)num_cpus, sizeof(perf_ring));
    struct pollfd *pfds = (struct pollfd *)calloc((size_t)num_cpus + 1, sizeof(struct pollfd));

    for (int cpu = 0; cpu < num_cpus; cpu++) {
        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_SOFTWARE;
        attr.size = sizeof(attr);
        attr.config = PERF_COUNT_SW_BPF_OUTPUT;
        attr.sample_type = PERF_SAMPLE_RAW;
        attr.wakeup_events = 1;

        int pfd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pfd < 0) {
            fprintf(stderr, "ERR:perf_ring_open(cpu=%d):errno=%d(%s)\n", cpu, errno, strerror(errno));
            return 7;
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
            return 9;
        }

        rings[cpu].fd = pfd;
        rings[cpu].base = mapped;
        rings[cpu].mmap_len = mmap_len;
        rings[cpu].data_size = ring_pages * page_size;
        pfds[cpu].fd = pfd;
        pfds[cpu].events = POLLIN;
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
        fprintf(stderr, "ERR:libssl_not_found\n");
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
            if (pfds[cpu].revents & POLLIN) {
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
        munmap(rings[cpu].base, rings[cpu].mmap_len);
        close(rings[cpu].fd);
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
