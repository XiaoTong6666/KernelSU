#include "linux/printk.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <trace/events/syscalls.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
#include <linux/compat.h>
#include <linux/sched/task_stack.h>
#endif

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/syscall_hook_manager.h"
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"

static syscall_fn_t orig_sys_setresuid;
#ifdef __NR_setuid
static syscall_fn_t orig_sys_setuid;
#endif
#ifdef __NR_setreuid
static syscall_fn_t orig_sys_setreuid;
#endif

static long __nocfi ksu_direct_hook_setresuid(const struct pt_regs *regs)
{
    uid_t old_uid = current_uid().val;
    long ret = orig_sys_setresuid(regs);

    if (ret < 0)
        return ret;

    ksu_handle_setresuid(old_uid, current_uid().val);
    return ret;
}

#ifdef __NR_setuid
static long __nocfi ksu_direct_hook_setuid(const struct pt_regs *regs)
{
    uid_t old_uid = current_uid().val;
    long ret = orig_sys_setuid(regs);

    if (ret < 0)
        return ret;

    ksu_handle_setresuid(old_uid, current_uid().val);
    return ret;
}
#endif

#ifdef __NR_setreuid
static long __nocfi ksu_direct_hook_setreuid(const struct pt_regs *regs)
{
    uid_t old_uid = current_uid().val;
    long ret = orig_sys_setreuid(regs);

    if (ret < 0)
        return ret;

    ksu_handle_setresuid(old_uid, current_uid().val);
    return ret;
}
#endif

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name, kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    if (ksu_tp_marker_reg_count() < 1) {
        // while install our tracepoint, mark our processes
        ksu_mark_running_process_locked();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while other tracepoint first added, mark all processes
        ksu_mark_all_process();
    }
    ksu_tp_marker_inc_reg_count();
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    ksu_tp_marker_dec_reg_count();
    if (ksu_tp_marker_reg_count() <= 0) {
        // while no tracepoint left, unmark all processes
        ksu_unmark_all_process();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while just our tracepoint left, unmark disallowed processes
        ksu_mark_running_process_locked();
    }
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
// sys_enter handler: redirect hooked syscalls to the dispatcher
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
#if defined(__x86_64__)
    if (unlikely(in_compat_syscall()))
#elif defined(__aarch64__)
    if (unlikely(is_compat_task()))
#endif
        return;

    if (ksu_dispatcher_nr < 0)
        return;

    if (ksu_has_syscall_hook(id)) {
        struct pt_regs *current_regs = task_pt_regs(current);

#if defined(__x86_64__)
        // Stash the original syscall number in ax.
        // We use ax because it currently just holds -ENOSYS and is safe to overwrite.
        current_regs->ax = id;
        current_regs->orig_ax = ksu_dispatcher_nr;
#elif defined(__aarch64__)
        PT_REGS_ORIG_SYSCALL(current_regs) = id;
        current_regs->syscallno = ksu_dispatcher_nr;
#endif
    }
}
#endif

void __init ksu_syscall_hook_manager_init(void)
{
    int ret;
    pr_info("hook_manager: ksu_hook_manager_init called\n");

#ifdef CONFIG_KRETPROBES
    syscall_regfunc_rp = init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
    syscall_unregfunc_rp = init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
#endif

    // Bootstrap UID transitions must work before a process is marked, so keep
    // them on direct syscall table hooks instead of the marked-only dispatcher.
    ksu_syscall_table_hook(__NR_setresuid, (syscall_fn_t)ksu_direct_hook_setresuid, &orig_sys_setresuid);
#ifdef __NR_setuid
    ksu_syscall_table_hook(__NR_setuid, (syscall_fn_t)ksu_direct_hook_setuid, &orig_sys_setuid);
#endif
#ifdef __NR_setreuid
    ksu_syscall_table_hook(__NR_setreuid, (syscall_fn_t)ksu_direct_hook_setreuid, &orig_sys_setreuid);
#endif

    // Register remaining syscall hooks via dispatcher
    ksu_register_syscall_hook(__NR_execve, ksu_hook_execve);
    ksu_register_syscall_hook(__NR_newfstatat, ksu_hook_newfstatat);
    ksu_register_syscall_hook(__NR_faccessat, ksu_hook_faccessat);
#ifdef __NR_execveat
    ksu_register_syscall_hook(__NR_execveat, ksu_hook_execveat);
#endif
#ifdef __NR_statx
    ksu_register_syscall_hook(__NR_statx, ksu_hook_statx);
#endif
#ifdef __NR_faccessat2
    ksu_register_syscall_hook(__NR_faccessat2, ksu_hook_faccessat2);
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_sys_enter(ksu_sys_enter_handler, NULL);
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\n");
    }
#endif

    ksu_setuid_hook_init();
    ksu_sucompat_init();
}

void __exit ksu_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: ksu_hook_manager_exit called\n");
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    unregister_trace_sys_enter(ksu_sys_enter_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("hook_manager: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif

    ksu_syscall_table_unhook(__NR_setresuid);
#ifdef __NR_setuid
    ksu_syscall_table_unhook(__NR_setuid);
#endif
#ifdef __NR_setreuid
    ksu_syscall_table_unhook(__NR_setreuid);
#endif
    ksu_unregister_syscall_hook(__NR_execve);
    ksu_unregister_syscall_hook(__NR_newfstatat);
    ksu_unregister_syscall_hook(__NR_faccessat);
#ifdef __NR_execveat
    ksu_unregister_syscall_hook(__NR_execveat);
#endif
#ifdef __NR_statx
    ksu_unregister_syscall_hook(__NR_statx);
#endif
#ifdef __NR_faccessat2
    ksu_unregister_syscall_hook(__NR_faccessat2);
#endif

    ksu_syscall_hook_exit();

    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
