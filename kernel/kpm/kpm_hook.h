/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 KSU KPM Backend.
 */

#ifndef _KPM_HOOK_INT_H_
#define _KPM_HOOK_INT_H_

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/barrier.h>
#include <asm/cacheflush.h>

/* Glue layer forward declarations (implemented in hook.c) */
int kpm_hotpatch_wrapper(void *addrs[], uint32_t values[], int cnt);
void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type);
void hook_mem_free(void *hook_mem);
void *hook_get_mem_from_origin(uint64_t origin_addr);

/* Replacement for KPM's dsb(ish) — use kernel memory barrier */
#define kpm_dsb_ish() smp_mb()

/* Replacement for KPM's isb() — kernel provides this */
/* isb() is available from <asm/barrier.h> */

/* Logging: replace KPM's logkv/logkvd/logkdd with kernel pr_* */
#define logkv(fmt, ...) pr_debug("kpm: " fmt, ##__VA_ARGS__)
#define logkvd(fmt, ...) pr_debug("kpm: " fmt, ##__VA_ARGS__)
#define logkdd(fmt, ...) pr_debug("kpm: " fmt, ##__VA_ARGS__)

/* Hook memory and text patching are handled in hook.c glue layer. */

/*
 * Hook install/uninstall via KSU's fixmap-based text patching.
 * Declared in hook/patch_memory.h.
 */

/* For flush_icache_all() replacement */
#define kpm_flush_icache_all()                                                                                         \
    do {                                                                                                               \
        flush_icache_range(0, ~0UL);                                                                                   \
    } while (0)

#endif /* _KPM_HOOK_INT_H_ */
