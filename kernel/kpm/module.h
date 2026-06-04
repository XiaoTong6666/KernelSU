/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_MODULE_H_
#define _KP_MODULE_H_

#include <asm-generic/module.h>
#include <linux/atomic.h>
#include <linux/elf.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include "kpmodule.h"

struct load_info {
    struct {
        const char *base;
        unsigned long size;
        const char *name, *version, *license, *author, *description;
    } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct {
        unsigned int sym, str, mod, info;
    } index;
};

struct kpm_module {
    struct {
        const char *base, *name, *version, *license, *author, *description;
    } info;

    char *args, *ctl_args;

    mod_initcall_t *init;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_exitcall_t *exit;

    unsigned int size;
    unsigned int text_size;
    unsigned int ro_size;

    void *start;

    atomic_t active_users;
    bool ready;
    bool unloading;
    wait_queue_head_t idle_wq;
    struct mutex op_lock;

    struct list_head list;
};

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved);
long load_module_path(const char *path, const char *args, void *__user reserved);
long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen);
long module_control1(const char *name, void *a1, void *a2, void *a3);
long unload_module(const char *name, void *__user reserved);
struct kpm_module *kpm_find_module(const char *name);

int get_module_nums();
int list_modules(char *out_names, int size);
int get_module_info(const char *name, char *out_info, int size);

#endif
