/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_UTILS_H_
#define _KP_UTILS_H_

#include <linux/compiler_attributes.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

int __must_check compat_copy_to_user(void __user *to, const void *from, unsigned long n);
long compat_strncpy_from_user(char *dest, const char __user *src, long count);
struct pt_regs *_task_pt_reg(struct task_struct *task);
void *__user copy_to_user_stack(const void *data, int len);
uid_t current_uid(void);
char *kf_strncat(char *dst, const char *src, size_t n);
int get_ap_mod_exclude(uid_t uid);
uint64_t get_random_u64(void);

#endif
