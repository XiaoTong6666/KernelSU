/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM accctl: SELinux AVC bypass via inline hook.
 * Only implements bypass_selinux + set_all_allow_sctx.
 *
 * NOT ported (KSU already provides equivalent or better):
 *   su_cred/commit_su/task_su → KSU escape_to_root_for_* + transive_to_domain
 *   task_ext per-task bypass → would conflict with KSU's task marking
 */
#ifndef _KPM_ACCCTL_H_
#define _KPM_ACCCTL_H_

int kpm_bypass_selinux(void);
void kpm_unbypass_selinux(void);
int kpm_set_all_allow_sctx(const char *sctx);

#endif
