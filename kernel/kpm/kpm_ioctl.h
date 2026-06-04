/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_IOCTL_H_
#define _KPM_IOCTL_H_

#include <uapi/asm-generic/errno.h>

#ifdef CONFIG_ARM64
int do_kpm_load(void __user *arg);
int do_kpm_unload(void __user *arg);
int do_kpm_control(void __user *arg);
int do_kpm_list(void __user *arg);
int do_kpm_info(void __user *arg);
#else
static inline int do_kpm_load(void __user *arg)
{
    return -EOPNOTSUPP;
}

static inline int do_kpm_unload(void __user *arg)
{
    return -EOPNOTSUPP;
}

static inline int do_kpm_control(void __user *arg)
{
    return -EOPNOTSUPP;
}

static inline int do_kpm_list(void __user *arg)
{
    return -EOPNOTSUPP;
}

static inline int do_kpm_info(void __user *arg)
{
    return -EOPNOTSUPP;
}
#endif

#endif
