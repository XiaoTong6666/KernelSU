/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM compatibility utilities — thin wrappers around kernel APIs
 * for KPM .o modules compiled with bare-metal toolchain.
 */
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/module.h>

#include "policy/allowlist.h"

static inline uid_t kpm_kernel_current_uid_value(void)
{
    return __kuid_val(current_uid());
}

#undef current_uid

int compat_copy_to_user(void __user *to, const void *from, unsigned long n)
{
    return copy_to_user(to, from, n);
}
EXPORT_SYMBOL(compat_copy_to_user);

long compat_strncpy_from_user(char *dst, const char __user *src, long count)
{
    return strncpy_from_user(dst, src, count);
}
EXPORT_SYMBOL(compat_strncpy_from_user);

struct pt_regs *_task_pt_reg(struct task_struct *task)
{
    return task_pt_regs(task);
}
EXPORT_SYMBOL(_task_pt_reg);

void *__user copy_to_user_stack(const void *data, int len)
{
    unsigned long addr = current_user_stack_pointer();

    addr -= len;
    addr &= ~7UL;

    return compat_copy_to_user((void __user *)addr, data, len) ? ERR_PTR(-EFAULT) : (void __user *)addr;
}
EXPORT_SYMBOL(copy_to_user_stack);

uid_t current_uid(void)
{
    return kpm_kernel_current_uid_value();
}
EXPORT_SYMBOL(current_uid);

char *kf_strncat(char *dst, const char *src, size_t n)
{
    return strncat(dst, src, n);
}
EXPORT_SYMBOL(kf_strncat);

int get_ap_mod_exclude(uid_t uid)
{
    return ksu_uid_should_umount(uid) ? 1 : 0;
}
EXPORT_SYMBOL(get_ap_mod_exclude);
