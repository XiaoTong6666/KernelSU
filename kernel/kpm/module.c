/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <uapi/asm-generic/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/version.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>

#include "infra/symbol_resolver.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/execmem.h>
#else
extern void *module_alloc(unsigned long size);
#endif

#include "module.h"
#include "relo.h"

#define SZ_128M 0x08000000
#define KPM_ALIGN(X) ALIGN(X, PAGE_SIZE)
#define ARCH_SHF_SMALL 0

/* Keep the legacy single-blob loader working across module_alloc and execmem kernels. */
static void *kpm_module_alloc(size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    return execmem_alloc(EXECMEM_MODULE_TEXT, size);
#else
    return module_alloc(size);
#endif
}

static void kpm_module_free(void *ptr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    execmem_free(ptr);
#else
    vfree(ptr);
#endif
}

static char *next_string(char *string, unsigned long *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1)
            return 0;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1)
            return 0;
    }
    return string;
}

/* Update size with this section: return offset. */
static long get_offset(struct kpm_module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
            return p + taglen + 1;
    }
    return 0;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0)
            return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx)
        return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx)
        return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct kpm_module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    // todo: tslf alloc all rwx and not page aligned
    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
            // const char *sname = info->secstrings + s->sh_name;
        }
        switch (m) {
        case 0: /* executable */
            mod->size = KPM_ALIGN(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = KPM_ALIGN(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            mod->size = KPM_ALIGN(mod->size);
            break;
        }
    }
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
        return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR))
        return false;
    return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct kpm_module *mod, const struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            if (!strncmp(name, "__gnu_lto", 9)) {
                pr_debug("kpm: "
                         "Please compile with -fno-common\n");
                ret = -ENOEXEC;
            }
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF: {
            unsigned long addr = find_kernel_symbol_exact(name);
            if (!addr)
                addr = kallsyms_lookup_name(name);
            if (!addr && !strcmp(name, "printk")) {
                addr = find_kernel_symbol_exact("_printk");
                if (!addr)
                    addr = kallsyms_lookup_name("_printk");
            }
            if (!addr) {
                pr_err("kpm: "
                       "unknown symbol: %s\n",
                       name);
                ret = -ENOEXEC;
                break;
            }
            sym[i].st_value = addr;
            break;
        }
        default:
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct kpm_module *mod, const struct load_info *info)
{
    int rc = 0;
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum)
            continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
            continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = kpm_apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = kpm_apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        }
        if (rc < 0)
            break;
    }
    return rc;
}

// todo: free .strtab and .symtab after relocation
static void layout_symtab(struct kpm_module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        /* Mark all sections sh_addr with their address in the temporary image. */
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct kpm_module *mod, struct load_info *info)
{
    // todo:
    pr_info("kpm: "
            "alloc module size: %x\n",
            mod->size);
    mod->start = kpm_module_alloc(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
    pr_debug("kpm: "
             "final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC))
            continue;

        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        pr_debug("kpm: "
                 "    %s %px %llx\n",
                 sname, dest, (unsigned long long)shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS)
            memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname))
            mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname))
            mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname))
            mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname))
            mod->exit = (mod_exitcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname))
            mod->info.base = (const char *)dest;
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;

    if (info->info.license)
        mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author)
        mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description)
        mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        pr_err("kpm: "
               "rewrite section error\n");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        pr_err("kpm: "
               "no .kpm.init or .kpm.exit section\n");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        pr_err("kpm: "
               "no .kpm.info section\n");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        pr_err("kpm: "
               "module name not found\n");
        return -ENOEXEC;
    }
    info->info.name = name;
    pr_debug("kpm: "
             "loading module: \n");
    pr_debug("kpm: "
             "    name: %s\n",
             name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        pr_debug("kpm: "
                 "module version not found\n");
        return -ENOEXEC;
    }
    info->info.version = version;
    pr_debug("kpm: "
             "    version: %s\n",
             version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    pr_debug("kpm: "
             "    license: %s\n",
             license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    pr_debug("kpm: "
             "    author: %s\n",
             author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    pr_debug("kpm: "
             "    description: %s\n",
             description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        pr_debug("kpm: "
                 "module has no symbols (stripped?)\n");
        return -ENOEXEC;
    }
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr)))
        return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr))
        return -ENOEXEC;
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff))
        return -ENOEXEC;
    return 0;
}

struct kpm_module modules = { 0 };
static DEFINE_MUTEX(module_lock);

static struct kpm_module *kpm_module_get_locked(const char *name)
{
    struct kpm_module *mod = kpm_find_module(name);

    if (!mod || !mod->ready || mod->unloading)
        return NULL;

    atomic_inc(&mod->active_users);
    return mod;
}

static void kpm_module_put(struct kpm_module *mod)
{
    if (atomic_dec_and_test(&mod->active_users))
        wake_up(&mod->idle_wq);
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = elf_header_check(info)))
        goto out;
    if ((rc = setup_load_info(info)))
        goto out;

    struct kpm_module *mod = (struct kpm_module *)vmalloc(sizeof(struct kpm_module));
    if (!mod)
        return -ENOMEM;
    memset(mod, 0, sizeof(struct kpm_module));
    atomic_set(&mod->active_users, 0);
    INIT_LIST_HEAD(&mod->list);
    init_waitqueue_head(&mod->idle_wq);
    mutex_init(&mod->op_lock);
    mod->info.name = info->info.name;

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            rc = -ENOMEM;
            goto free1;
        }
        strcpy(mod->args, args);
    }

    mutex_lock(&module_lock);
    if (kpm_find_module(info->info.name)) {
        mutex_unlock(&module_lock);
        pr_debug("kpm: "
                 "%s exist\n",
                 info->info.name);
        rc = -EEXIST;
        goto free1;
    }
    list_add_tail(&mod->list, &modules.list);
    mutex_unlock(&module_lock);

    layout_sections(mod, info);
    layout_symtab(mod, info);

    if ((rc = move_module(mod, info)))
        goto free;
    if ((rc = simplify_symbols(mod, info)))
        goto free;
    if ((rc = apply_relocations(mod, info)))
        goto free;

    flush_icache_range(mod->start, (unsigned long)mod->start + mod->text_size);

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        pr_info("kpm: "
                "[%s] succeed with [%s] \n",
                mod->info.name, args);
        mutex_lock(&module_lock);
        mod->ready = true;
        mutex_unlock(&module_lock);
        goto out;
    } else {
        pr_info("kpm: "
                "[%s] failed with [%s] error: %ld, try exit ...\n",
                mod->info.name, args, rc);
        (*mod->exit)(reserved);
    }

free:
    mutex_lock(&module_lock);
    if (!list_empty(&mod->list))
        list_del_init(&mod->list);
    mutex_unlock(&module_lock);
    if (mod->args)
        kvfree(mod->args);
    kpm_module_free(mod->start);
free1:
    kvfree(mod);
out:
    return rc;
}

// todo: lock
long unload_module(const char *name, void *__user reserved)
{
    if (!name)
        return -EINVAL;
    pr_err("kpm: "
           "name: %s\n",
           name);

    mutex_lock(&module_lock);
    long rc = 0;

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod || !mod->ready || mod->unloading) {
        rc = -ENOENT;
        goto out;
    }
    if (!mutex_trylock(&mod->op_lock)) {
        rc = -EBUSY;
        goto out;
    }
    list_del_init(&mod->list);
    mod->ready = false;
    mod->unloading = true;
    mutex_unlock(&module_lock);

    wait_event(mod->idle_wq, atomic_read(&mod->active_users) == 0);
    rc = (*mod->exit)(reserved);
    mutex_unlock(&mod->op_lock);

    if (mod->args)
        kvfree(mod->args);
    if (mod->ctl_args)
        kvfree(mod->ctl_args);

    kpm_module_free(mod->start);
    kvfree(mod);

    pr_info("kpm: "
            "name: %s, rc: %ld\n",
            name, rc);
    return rc;

out:
    mutex_unlock(&module_lock);
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    struct file *filp = NULL;
    pr_debug("kpm: "
             "%s\n",
             path);
    if (!path)
        return -EINVAL;

    filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        pr_err("kpm: "
               "open module: %s error\n",
               path);
        rc = PTR_ERR(filp);
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    pr_debug("kpm: "
             "module size: %llx\n",
             (unsigned long long)len);
    vfs_llseek(filp, 0, SEEK_SET);

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        goto close;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    kernel_read(filp, data, len, &pos);
    filp_close(filp, 0);
    filp = NULL;

    if (pos != len) {
        pr_err("kpm: "
               "read module: %s error\n",
               path);
        rc = -EIO;
        goto free;
    }

    rc = load_module(data, len, args, "load-file", reserved);
free:
    kvfree(data);
close:
    if (!IS_ERR_OR_NULL(filp))
        filp_close(filp, 0);
out:
    return rc;
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!name || !ctl_args)
        return -EINVAL;
    int args_len = strlen(ctl_args);
    if (args_len <= 0)
        return -EINVAL;

    pr_info("kpm: "
            "name %s, args: %s\n",
            name, ctl_args);

    long rc = 0;
    mutex_lock(&module_lock);
    struct kpm_module *mod = kpm_module_get_locked(name);
    mutex_unlock(&module_lock);
    if (!mod) {
        rc = -ENOENT;
        return rc;
    }

    if (!mutex_trylock(&mod->op_lock)) {
        kpm_module_put(mod);
        return -EBUSY;
    }
    if (!mod->ctl0 || !*mod->ctl0) {
        pr_err("kpm: "
               "no ctl0\n");
        rc = -ENOSYS;
        goto out_put;
    }

    char *new_ctl_args = vmalloc(args_len + 1);
    if (!new_ctl_args) {
        rc = -ENOMEM;
        goto out_put;
    }

    strcpy(new_ctl_args, ctl_args);

    if (mod->ctl_args)
        kvfree(mod->ctl_args);
    mod->ctl_args = new_ctl_args;

    rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);

    pr_info("kpm: "
            "name: %s, rc: %ld\n",
            name, rc);

out_put:
    mutex_unlock(&mod->op_lock);
    kpm_module_put(mod);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    pr_info("kpm: "
            "name %s, a1: %px, a2: %px, a3: %px\n",
            name, a1, a2, a3);
    long rc = 0;
    mutex_lock(&module_lock);
    struct kpm_module *mod = kpm_module_get_locked(name);
    mutex_unlock(&module_lock);
    if (!mod) {
        rc = -ENOENT;
        return rc;
    }

    if (!mutex_trylock(&mod->op_lock)) {
        kpm_module_put(mod);
        return -EBUSY;
    }
    if (!mod->ctl1 || !*mod->ctl1) {
        pr_err("kpm: "
               "no ctl1\n");
        rc = -ENOSYS;
        goto out_put;
    }

    rc = (*mod->ctl1)(a1, a2, a3);

    pr_info("kpm: "
            "name: %s, rc: %ld\n",
            name, rc);

out_put:
    mutex_unlock(&mod->op_lock);
    kpm_module_put(mod);
    return rc;
}

struct kpm_module *kpm_find_module(const char *name)
{
    struct kpm_module *pos;
    list_for_each_entry (pos, &modules.list, list) {
        if (!strcmp(name, pos->info.name)) {
            return pos;
        }
    }
    return 0;
}

int get_module_nums()
{
    mutex_lock(&module_lock);

    struct kpm_module *pos;
    int n = 0;
    list_for_each_entry (pos, &modules.list, list) {
        if (!pos->ready || pos->unloading)
            continue;
        n++;
    }
    mutex_unlock(&module_lock);

    pr_debug("kpm: "
             "%d\n",
             n);
    return n;
}

int list_modules(char *out_names, int size)
{
    mutex_lock(&module_lock);

    struct kpm_module *pos;
    int off = 0;
    list_for_each_entry (pos, &modules.list, list) {
        if (!pos->ready || pos->unloading)
            continue;
        off += snprintf(out_names + off, size - 1 - off, "%s\n", pos->info.name);
    }
    if (off > 0)
        out_names[off - 1] = '\0';

    mutex_unlock(&module_lock);
    return off;
}

int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0)
        return 0;
    mutex_lock(&module_lock);

    struct kpm_module *mod = kpm_module_get_locked(name);
    mutex_unlock(&module_lock);
    if (!mod) {
        return -ENOENT;
    }

    int sz = snprintf(out_info, size - 1,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name, mod->info.version, mod->info.license, mod->info.author, mod->info.description,
                      mod->args);

    if (sz > 0)
        out_info[sz - 1] = '\0';
    pr_debug("kpm: "
             "%s",
             out_info);

    kpm_module_put(mod);
    return sz;
}

void __init kpm_module_init(void)
{
    INIT_LIST_HEAD(&modules.list);
}
