/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 KPM Backend.
 * KPM ioctl handlers for KSU supercall dispatch.
 */

#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/printk.h>

#include "uapi/supercall.h"
#include "kpm/module.h"

#define KPM_IOCTL_MAX_OUT 16384

int do_kpm_load(void __user *arg)
{
    struct kpm_load_cmd cmd;
    long rc;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    cmd.path[sizeof(cmd.path) - 1] = '\0';
    cmd.args[sizeof(cmd.args) - 1] = '\0';

    rc = load_module_path(cmd.path, cmd.args, NULL);
    pr_info("kpm: load %s args=%s rc=%ld\n", cmd.path, cmd.args, rc);
    return (int)rc;
}

int do_kpm_unload(void __user *arg)
{
    struct kpm_unload_cmd cmd;
    long rc;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    cmd.name[sizeof(cmd.name) - 1] = '\0';

    rc = unload_module(cmd.name, NULL);
    pr_info("kpm: unload %s rc=%ld\n", cmd.name, rc);
    return (int)rc;
}

int do_kpm_control(void __user *arg)
{
    struct kpm_control_cmd cmd;
    long rc;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    cmd.name[sizeof(cmd.name) - 1] = '\0';
    cmd.ctl_args[sizeof(cmd.ctl_args) - 1] = '\0';

    rc = module_control0(cmd.name, cmd.ctl_args, (char __user *)cmd.out_msg, cmd.out_len);
    pr_info("kpm: control %s args=%s rc=%ld\n", cmd.name, cmd.ctl_args, rc);
    return (int)rc;
}

int do_kpm_list(void __user *arg)
{
    struct kpm_list_cmd cmd;
    char *buf;
    int rc;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    if (cmd.out_len <= 0 || cmd.out_len > KPM_IOCTL_MAX_OUT)
        return -EINVAL;

    buf = kzalloc(cmd.out_len, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    rc = list_modules(buf, cmd.out_len);
    if (rc >= 0 && copy_to_user((void __user *)cmd.out_buf, buf, cmd.out_len))
        rc = -EFAULT;

    kfree(buf);
    pr_info("kpm: list rc=%d\n", rc);
    return rc;
}

int do_kpm_info(void __user *arg)
{
    struct kpm_info_cmd cmd;
    char *buf;
    int rc;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    if (cmd.out_len <= 0 || cmd.out_len > KPM_IOCTL_MAX_OUT)
        return -EINVAL;
    cmd.name[sizeof(cmd.name) - 1] = '\0';

    buf = kzalloc(cmd.out_len, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    rc = get_module_info(cmd.name, buf, cmd.out_len);
    if (rc >= 0 && copy_to_user((void __user *)cmd.out_buf, buf, cmd.out_len))
        rc = -EFAULT;

    kfree(buf);
    pr_info("kpm: info %s rc=%d\n", cmd.name, rc);
    return rc;
}
