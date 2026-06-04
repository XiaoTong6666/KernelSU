/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM syscall hook API — ported from KernelPatch patch/common/syscall.c.
 * Provides hook_syscalln / unhook_syscalln via already-ported fp_hook_wrap / hook_wrap.
 */

#include "syscall.h"

#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

/* Syscall tables — resolved at init via kallsyms */
uintptr_t *sys_call_table;
EXPORT_SYMBOL(sys_call_table);

uintptr_t *compat_sys_call_table;
EXPORT_SYMBOL(compat_sys_call_table);

int has_syscall_wrapper;
EXPORT_SYMBOL(has_syscall_wrapper);

int has_config_compat;
EXPORT_SYMBOL(has_config_compat);

typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)(void);
typedef long (*raw_syscall1_f)(long arg0);
typedef long (*raw_syscall2_f)(long arg0, long arg1);
typedef long (*raw_syscall3_f)(long arg0, long arg1, long arg2);
typedef long (*raw_syscall4_f)(long arg0, long arg1, long arg2, long arg3);
typedef long (*raw_syscall5_f)(long arg0, long arg1, long arg2, long arg3, long arg4);
typedef long (*raw_syscall6_f)(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

/* Name tables — empty on KSU (no predata). Filled lazily on first inline hook. */

sc_name_t syscall_name_table[460] = {
#include "sysnames_native.inc"
    EXPORT_SYMBOL(syscall_name_table);

sc_name_t compat_syscall_name_table[460] = {
#include "sysnames_compat.inc"
    EXPORT_SYMBOL(compat_syscall_name_table);

const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    const char __user *uptr;

    if (has_config_compat) {
        if (a0) {
            u32 compat_ptr_val;

            if (copy_from_user(&compat_ptr_val, (u32 __user *)a1 + nr, sizeof(compat_ptr_val)))
                return ERR_PTR(-EFAULT);
            return (const char __user *)(uintptr_t)compat_ptr_val;
        }

        if (copy_from_user(&uptr, (const char __user *const __user *)a1 + nr, sizeof(uptr)))
            return ERR_PTR(-EFAULT);
        return uptr;
    }

    if (copy_from_user(&uptr, (const char __user *const __user *)a0 + nr, sizeof(uptr)))
        return ERR_PTR(-EFAULT);
    return uptr;
}
EXPORT_SYMBOL(get_user_arg_ptr);

int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val)
{
    if (has_config_compat) {
        if (a0) {
            u32 compat_ptr_val = (u32)val;

            return copy_to_user((u32 __user *)a1 + nr, &compat_ptr_val, sizeof(compat_ptr_val));
        }

        return copy_to_user((uintptr_t __user *)a1 + nr, &val, sizeof(val));
    }

    return copy_to_user((uintptr_t __user *)a0 + nr, &val, sizeof(val));
}
EXPORT_SYMBOL(set_user_arg_ptr);

/*
 * Resolve a syscall function address by number.
 * Tries cached table first, then kallsyms with naming conventions.
 */
uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    sc_name_t *table = is_compat ? compat_syscall_name_table : syscall_name_table;
    const char *name;
    char symname[80];
    unsigned long addr = 0;
    if (nr < 0 || nr >= 460)
        return 0;

    /* Return cached address if already resolved */
    if (table[nr].addr)
        return table[nr].addr;

    name = table[nr].name;
    if (!name)
        return 0;

    /*
     * Resolve syscall function address by trying naming conventions:
     *   __arm64_sys_<name> (.cfi_jt / .cfi / direct)
     *   __arm64_compat_sys_<name> (compat)
     *   sys_<name> (older kernels)
     */
    const char *prefix = is_compat ? "__arm64_compat_" : "__arm64_";

    static const char *suffixes[] = { ".cfi_jt", ".cfi", "" };
    for (int j = 0; j < 3 && !addr; j++) {
        snprintf(symname, sizeof(symname), "%s%s%s", prefix, name, suffixes[j]);
        addr = kallsyms_lookup_name(symname);
    }
    /* Fallback: bare sys_<name> (older kernels) */
    if (!addr) {
        snprintf(symname, sizeof(symname), "%s", name);
        addr = kallsyms_lookup_name(symname);
    }

    if (addr) {
        table[nr].addr = addr;
        return addr;
    }
    return 0;
}
EXPORT_SYMBOL(syscalln_name_addr);

uintptr_t syscalln_addr(int nr, int is_compat)
{
    uintptr_t *table = is_compat ? compat_sys_call_table : sys_call_table;
    if (table)
        return table[nr];
    return syscalln_name_addr(nr, is_compat);
}
EXPORT_SYMBOL(syscalln_addr);

long raw_syscall0(long nr)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
}
EXPORT_SYMBOL(raw_syscall0);

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}
EXPORT_SYMBOL(raw_syscall1);

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}
EXPORT_SYMBOL(raw_syscall2);

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}
EXPORT_SYMBOL(raw_syscall3);

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}
EXPORT_SYMBOL(raw_syscall4);

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}
EXPORT_SYMBOL(raw_syscall5);

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = syscalln_addr(nr, 0);

    if (has_syscall_wrapper) {
        struct pt_regs regs = { 0 };

        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        regs.regs[5] = arg5;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall6_f)addr)(arg0, arg1, arg2, arg3, arg4, arg5);
}
EXPORT_SYMBOL(raw_syscall6);

/*
 * FP (function pointer) wrappers — replace sys_call_table[nr] entry.
 * Uses already-ported fp_hook_wrap / fp_hook_unwrap.
 */
hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t *table = is_compat ? compat_sys_call_table : sys_call_table;
    if (!table)
        return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper)
        narg = 1;
    return fp_hook_wrap((uintptr_t)(table + nr), narg, before, after, udata);
}
EXPORT_SYMBOL(fp_wrap_syscalln);

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t *table = is_compat ? compat_sys_call_table : sys_call_table;
    if (!table)
        return;
    fp_hook_unwrap((uintptr_t)(table + nr), before, after);
}
EXPORT_SYMBOL(fp_unwrap_syscalln);

/*
 * Inline wrappers — hook the syscall function body.
 * Uses already-ported hook_wrap / hook_unwrap.
 */
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr)
        return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper)
        narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}
EXPORT_SYMBOL(inline_wrap_syscalln);

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (addr)
        hook_unwrap_remove((void *)addr, before, after, 1);
}
EXPORT_SYMBOL(inline_unwrap_syscalln);

/*
 * Auto-choice wrappers — prefer FP if sys_call_table is available,
 * fall back to inline hook otherwise.
 */
hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (sys_call_table)
        return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
EXPORT_SYMBOL(hook_syscalln);

void unhook_syscalln(int nr, void *before, void *after)
{
    if (sys_call_table)
        return fp_unwrap_syscalln(nr, 0, before, after);
    return inline_unwrap_syscalln(nr, 0, before, after);
}
EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (compat_sys_call_table)
        return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}
EXPORT_SYMBOL(hook_compat_syscalln);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (compat_sys_call_table)
        return fp_unwrap_syscalln(nr, 1, before, after);
    return inline_unwrap_syscalln(nr, 1, before, after);
}
EXPORT_SYMBOL(unhook_compat_syscalln);

/*
 * Initialize syscall tables at module init.
 */
void __init kpm_syscall_init(void)
{
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (sys_call_table)
        pr_info("kpm: sys_call_table at %px\n", sys_call_table);

    compat_sys_call_table = (void *)kallsyms_lookup_name("compat_sys_call_table");
    if (compat_sys_call_table)
        pr_info("kpm: compat_sys_call_table at %px\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (kallsyms_lookup_name("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (kallsyms_lookup_name("compat_sys_call_table") || kallsyms_lookup_name("compat_sys_openat"))
            has_config_compat = 1;
        if (kallsyms_lookup_name("__arm64_sys_openat"))
            has_syscall_wrapper = 1;
    }
    pr_info("kpm: has_syscall_wrapper=%d has_config_compat=%d\n", has_syscall_wrapper, has_config_compat);
}
