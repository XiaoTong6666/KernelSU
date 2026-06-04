/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM accctl: SELinux AVC bypass via inline hook.
 *
 * Only bypass_selinux (hook avc_denied + slow_avc_audit)
 * and set_all_allow_sctx (global allow SID). Uses void *
 * for hook backups to avoid direct SELinux type dependencies.
 */

#include "accctl.h"
#include "hook.h"

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "infra/symbol_resolver.h"

#define KPM_SCONTEXT_LEN 256

static char all_allow_sctx[KPM_SCONTEXT_LEN];
static u32 all_allow_sid;

/* Single-type backup function pointer — used for both hooks */
typedef int (*avc_hook_fn_t)(void *, void *, void *, void *, void *, void *, void *, void *, void *);

int kpm_set_all_allow_sctx(const char *sctx)
{
    u32 sid;
    int rc;

    if (!sctx || !sctx[0]) {
        all_allow_sctx[0] = '\0';
        WRITE_ONCE(all_allow_sid, 0);
        pr_info("kpm: clear all-allow scontext\n");
        return 0;
    }

    rc = security_secctx_to_secid(sctx, strlen(sctx), &sid);
    if (!rc && sid) {
        strncpy(all_allow_sctx, sctx, sizeof(all_allow_sctx) - 1);
        all_allow_sctx[sizeof(all_allow_sctx) - 1] = '\0';
        WRITE_ONCE(all_allow_sid, sid);
        pr_info("kpm: set all-allow scontext: %s sid=%u\n", all_allow_sctx, all_allow_sid);
    } else {
        pr_err("kpm: secctx_to_secid %s failed: %d\n", sctx ? sctx : "(null)", rc);
    }
    return rc;
}
EXPORT_SYMBOL(kpm_set_all_allow_sctx);

/*
 * avc_denied hook — override AVC denial decisions.
 * Parameters are treated opaquely (void *) because the real types
 * (struct selinux_state, struct av_decision, etc.) are SELinux internals.
 * We only need to:
 *   1. Call the backup function when not bypassing
 *   2. Write avd->allowed = 0xffffffff when bypassing
 *
 * struct av_decision layout (stable across kernel versions):
 *   u32 allowed;     // offset 0
 *   u32 auditallow;  // offset 4
 *   u32 auditdeny;   // offset 8
 * (and possibly more fields after)
 */

static void *avc_denied_backup;
static unsigned long avc_denied_hook_addr;

static int avc_denied_replace(void *state, void *ssid, void *tsid, void *tclass, void *requested, void *driver,
                              void *xperm, void *flags, void *avd)
{
    u32 sid = (u32)(u64)ssid;
    u32 allow_sid = READ_ONCE(all_allow_sid);

    if (allow_sid && sid == allow_sid) {
        u32 *p = (u32 *)avd;
        p[0] = 0xffffffff; /* allowed */
        p[1] = 0; /* auditallow */
        p[2] = 0; /* auditdeny */
        return 0;
    }

    if (avc_denied_backup) {
        return ((avc_hook_fn_t)avc_denied_backup)(state, ssid, tsid, tclass, requested, driver, xperm, flags, avd);
    }
    return 0;
}

/*
 * slow_avc_audit hook — suppress audit messages when bypassing.
 */

static void *slow_avc_audit_backup;
static unsigned long slow_avc_audit_hook_addr;

static int slow_avc_audit_replace(void *state, void *ssid, void *tsid, void *tclass, void *requested, void *audited,
                                  void *denied, void *result, void *a)
{
    u32 sid = (u32)(u64)ssid;
    u32 allow_sid = all_allow_sid;
    smp_mb();

    if (allow_sid && sid == allow_sid)
        return 0;

    if (slow_avc_audit_backup) {
        return ((avc_hook_fn_t)slow_avc_audit_backup)(state, ssid, tsid, tclass, requested, audited, denied, result, a);
    }
    return 0;
}

int kpm_bypass_selinux(void)
{
    unsigned long addr;
    hook_err_t err;

    addr = find_kernel_symbol_exact("avc_denied");
    if (addr) {
        err = hook((void *)addr, (void *)avc_denied_replace, &avc_denied_backup);
        if (err)
            pr_err("kpm: hook avc_denied(%lx) failed: %d\n", addr, err);
        else {
            avc_denied_hook_addr = addr;
            pr_info("kpm: hooked avc_denied at %lx\n", addr);
        }
    } else {
        pr_warn("kpm: avc_denied not found\n");
    }

    addr = find_kernel_symbol_exact("slow_avc_audit");
    if (addr) {
        err = hook((void *)addr, (void *)slow_avc_audit_replace, &slow_avc_audit_backup);
        if (err)
            pr_err("kpm: hook slow_avc_audit(%lx) failed: %d\n", addr, err);
        else {
            slow_avc_audit_hook_addr = addr;
            pr_info("kpm: hooked slow_avc_audit at %lx\n", addr);
        }
    } else {
        pr_warn("kpm: slow_avc_audit not found\n");
    }

    return 0;
}

void kpm_unbypass_selinux(void)
{
    if (slow_avc_audit_hook_addr) {
        unhook((void *)slow_avc_audit_hook_addr);
        slow_avc_audit_hook_addr = 0;
        slow_avc_audit_backup = NULL;
    }

    if (avc_denied_hook_addr) {
        unhook((void *)avc_denied_hook_addr);
        avc_denied_hook_addr = 0;
        avc_denied_backup = NULL;
    }
}
